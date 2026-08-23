/* Phase 3 verification — quizzes, certificates, Q&A, notes.
   Run against a THROWAWAY DB:  DB_NAME=phase3_test node index.js        */
const BASE = "http://localhost:5000";
let pass = 0;
let fail = 0;
const ok = (name, cond, extra = "") => {
  if (cond) { pass++; console.log(`  PASS ${name}`); }
  else { fail++; console.log(`  FAIL ${name} ${extra}`); }
};

async function j(method, path, body, token) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers: {
      "Content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await res.json(); } catch {}
  return { status: res.status, data };
}

const AUTHOR = { displayName: "Author X", email: "a@phase3.test", photoURL: "" };
const STUDENT = { displayName: "Stu Dent", email: "s@phase3.test", photoURL: "" };

const run = async () => {
  const tA = (await j("POST", "/user", AUTHOR)).data.token;
  const tS = (await j("POST", "/user", STUDENT)).data.token;

  /* --- seed paid course with 2 lessons --- */
  const add = await j("POST", "/course/add", {
    title: "Phase3 Course",
    price: "20",
    description: "<p>x</p>",
    sections: [
      { title: "S1", lessons: [{ title: "L1", videoUrl: "http://x/1.mp4" }, { title: "L2", videoUrl: "http://x/2.mp4" }] },
    ],
  }, tA);
  const cid = add.data.insertedId;

  /* --- quiz authoring --- */
  let r = await j("PUT", `/quiz/${cid}`, { questions: [{ q: "2+2?", options: ["3", "4"], answerIdx: 1 }] }, tS);
  ok("non-owner cannot author quiz", r.status === 403);

  r = await j("PUT", `/quiz/${cid}`, {
    passScore: 70,
    questions: [
      { q: "2+2?", options: ["3", "4"], answerIdx: 1 },
      { q: "Sky color?", options: ["Blue", "Red"], answerIdx: 0 },
    ],
  }, tA);
  ok("owner saves quiz", r.data?.count === 2);

  const anonQuiz = await j("GET", `/quiz/${cid}`);
  ok("learner copy hides answer key", anonQuiz.data.questions[0].answerIdx === undefined && anonQuiz.data.questions.length === 2);
  const ownerQuiz = await j("GET", `/quiz/${cid}`, null, tA);
  ok("author copy keeps answer key", ownerQuiz.data.questions[0].answerIdx === 1);

  /* --- grading + enrollment gate --- */
  r = await j("POST", `/quiz/${cid}/attempt`, { answers: [1, 0] }, tS);
  ok("un-enrolled attempt blocked", r.status === 403);

  await j("POST", "/payment", { courseId: cid, price: "20" }, tS); // student buys
  r = await j("POST", `/quiz/${cid}/attempt`, { answers: [0, 1] }, tS);
  ok("wrong answers graded 0%", r.data.score === 0 && r.data.passed === false);
  ok("review reveals correct answers after submit", r.data.review[0].correct === false && r.data.review[0].answerIdx === 1);

  r = await j("POST", `/quiz/${cid}/attempt`, { answers: [1, 0] }, tS);
  ok("perfect score passes", r.data.score === 100 && r.data.passed === true);
  const latest = await j("GET", `/quiz/${cid}/attempts/me`, null, tS);
  ok("latest attempt stored", latest.data?.passed === true && latest.data?.score === 100);

  /* --- certificate gating --- */
  r = await j("POST", `/certificates/${cid}`, null, tS);
  ok("certificate blocked before finishing lessons", r.status === 403 && /lessons/i.test(r.data.message));

  await j("PATCH", `/progress/${STUDENT.email}`, { courseId: cid, lessons: ["0"] }, tS);
  r = await j("POST", `/certificates/${cid}`, null, tS);
  ok("certificate blocked with 1/2 lessons", r.status === 403);

  await j("PATCH", `/progress/${STUDENT.email}`, { courseId: cid, lessons: ["0", "1"] }, tS);
  r = await j("POST", `/certificates/${cid}`, null, tS);
  ok("certificate issued when eligible", !!r.data?.code && r.data.studentName === "Stu Dent");
  const code = r.data.code;

  const dup = await j("POST", `/certificates/${cid}`, null, tS);
  ok("re-claim returns same certificate", dup.data.code === code);

  const verify = await j("GET", `/certificates/verify/${code.toLowerCase()}`);
  ok("public verification works (case-insensitive)", verify.data.valid === true && !verify.data.email);
  const bad = await j("GET", "/certificates/verify/AVN-NOPE");
  ok("unknown code → invalid", bad.status === 404 || bad.data.valid === false);

  /* --- quiz gate on certificate --- */
  // new student buys but skips quiz
  const T3 = (await j("POST", "/user", { displayName: "Skip Quiz", email: "q@phase3.test", photoURL: "" })).data.token;
  await j("POST", "/payment", { courseId: cid, price: "20" }, T3);
  await j("PATCH", `/progress/q@phase3.test`, { courseId: cid, lessons: ["0", "1"] }, T3);
  r = await j("POST", `/certificates/${cid}`, null, T3);
  ok("certificate blocked without passing quiz", r.status === 403 && /quiz/i.test(r.data.message));

  /* --- Q&A --- */
  r = await j("POST", `/questions/${cid}`, { text: "How do I start?", lessonId: 0, name: STUDENT.displayName, photo: "" }, tS);
  ok("student posts question", !!r.data?.acknowledged || !!r.data?.insertedId);
  const qid = r.data.insertedId;

  r = await j("POST", `/questions/${qid}/reply`, { text: "From lecture 1!", name: AUTHOR.displayName }, tA);
  ok("author reply accepted", r.data.acknowledged === true);

  let qs = await j("GET", `/questions/${cid}`);
  ok("reply flagged as instructor", qs.data[0].replies[0].isInstructor === true);
  ok("student question not flagged as author", qs.data[0].isAuthor === false);

  r = await j("DELETE", `/questions/${qid}`, null, tA); // not owner → no delete
  ok("strangers cannot delete a question", r.data.deletedCount === 0);
  r = await j("DELETE", `/questions/${qid}`, null, tS);
  ok("author deletes own question", r.data.deletedCount === 1);

  /* --- notes --- */
  r = await j("PATCH", `/notes/${cid}`, { notes: [{ lessonId: 1, at: 95, text: "<i>Key idea</i>" }] }, tS);
  ok("notes saved", r.data.acknowledged === true);
  let notes = await j("GET", `/notes/${cid}`, null, tS);
  ok("notes sanitized to plain text", notes.data[0].text === "Key idea" && notes.data[0].at === 95);
  notes = await j("GET", `/notes/${cid}`, null, tA);
  ok("notes are private per user", notes.data.length === 0);

  /* cleanup */
  await j("DELETE", `/course/delete/${cid}`, null, tA);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
};

run().catch((e) => { console.error(e); process.exit(1); });
