/* Phase 1 security verification — runs against a THROWAWAY DB (DB_NAME env). */
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

const A = { displayName: "Owner A", email: "e2e-a@phase1.test", photoURL: "", role: "admin-hack-attempt" };
const B = { displayName: "Rogue B", email: "e2e-b@phase1.test", photoURL: "" };

const run = async () => {
  /* --- auth + roles --- */
  const loginA = await j("POST", "/user", A);
  ok("login A returns token", !!loginA.data?.token);
  const tA = loginA.data.token;
  const loginB = await j("POST", "/user", B);
  const tB = loginB.data.token;

  // role injection attempt must be stripped → decoded role is student
  const meA = await j("GET", "/users/me", null, tA);
  ok("/users/me works with own token", meA.status === 200 && meA.data?.email === A.email);
  ok("client-supplied role was NOT stored", !meA.data?.role || meA.data.role === "student", `role=${meA.data?.role}`);

  const anonMe = await fetch(`${BASE}/users/me`);
  ok("/users/me anonymous → 401", anonMe.status === 401);

  const crossUser = await j("GET", `/user/${B.email}`, null, tA);
  ok("reading another user's profile → 403", crossUser.status === 403);

  const roster = await j("GET", "/user", null, tA);
  ok("user roster is admin-only → 403", roster.status === 403);

  /* --- course ownership --- */
  const add = await j("POST", "/course/add", {
    title: "Phase1 Sec Test",
    price: "10",
    description: '<p onclick="alert(1)">Safe text</p><script>evil()</script>',
    authorEmail: "spoofed@attacker.test",
    author: A.displayName,
    category: "React",
    lave: "beginner",
    milestoneList: [{ title: "L1", videoUrl: "http://x/v.mp4" }],
  }, tA);
  ok("course add acknowledged", add.data?.acknowledged === true);
  const courseId = add.data?.insertedId;

  const mine = await j("GET", `/course/find/${A.email}`, null, tB);
  ok("find/:email of ANOTHER user → 403", mine.status === 403);

  const editOther = await j("PATCH", `/course/edit/${courseId}`, { title: "hacked" }, tB);
  ok("editing someone else's course → 403", editOther.status === 403);
  const delOther = await j("DELETE", `/course/delete/${courseId}`, null, tB);
  ok("deleting someone else's course → 403", delOther.status === 403);

  const editOwn = await j("PATCH", `/course/edit/${courseId}`, { title: "renamed" }, tA);
  ok("owner can edit own course", editOwn.data?.matchedCount === 1);

  /* --- forged-enrollment protection --- */
  const forge = await j("POST", "/payment", {
    courseId,
    price: "10",
    customerEmail: B.email, // B tries to gift themselves enrollment on A's course
    authorEmail: A.email,
  }, tB);
  ok("payment POST accepted (auth)", forge.data?.acknowledged === true);
  const myOrders = await j("GET", "/payments/me", null, tB);
  ok("forged customerEmail overwritten to token owner",
    myOrders.data?.[0]?.customerEmail === B.email &&
    !myOrders.data.some((p) => p.customerEmail !== B.email));

  const allPayments = await j("GET", "/payment", null, tA);
  ok("full payment ledger is admin-only → 403", allPayments.status === 403);

  /* --- progress self-scoping --- */
  const progOther = await j("GET", `/progress/${A.email}`, null, tB);
  ok("reading someone else's progress → 403", progOther.status === 403);
  const progSelf = await j("PATCH", `/progress/${B.email}`, { courseId, lessons: ["0"] }, tB);
  ok("saving own progress works", progSelf.data?.acknowledged === true);

  /* cleanup */
  await j("DELETE", `/course/delete/${courseId}`, null, tA);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
};

run().catch((e) => { console.error(e); process.exit(1); });
