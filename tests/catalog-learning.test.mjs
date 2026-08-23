/* Phase 2 verification — reviews, catalog v2, wishlist, progress state.
   Run against a THROWAWAY DB:  DB_NAME=phase2_test node index.js        */
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

const U = { displayName: "Learner T", email: "p2@phase2.test", photoURL: "" };

const run = async () => {
  const { data: login } = await j("POST", "/user", U);
  const t = login.token;

  /* --- seed 3 courses via /course/add --- */
  const seed = [
    { title: "Alpha React", category: "React", lave: "beginner", price: "50" },
    { title: "Beta Node", category: "Node", lave: "advance", price: "30" },
    { title: "Gamma PHP", category: "PHP", lave: "mid-lave", price: "90" },
  ].map((c) => ({
    ...c,
    description: "<p>d</p>",
    sections: [{ title: `${c.title} Section`, lessons: [{ title: "L1", videoUrl: "http://x/v.mp4" }] }],
  }));
  const ids = [];
  for (const s of seed) {
    const r = await j("POST", "/course/add", s, t);
    ids.push(r.data.insertedId);
  }
  ok("seeded 3 courses with multi-section payload", ids.length === 3);

  /* --- catalog v2 --- */
  let r = await j("GET", "/courses/search?limit=2&page=1");
  ok("search paginated total", r.data.total === 3 && r.data.items.length === 2 && r.data.pages === 2);
  r = await j("GET", "/courses/search?q=alpha");
  ok("q filter matches title only", r.data.total === 1 && r.data.items[0].title === "Alpha React");
  r = await j("GET", "/courses/search?category=Node");
  ok("category filter", r.data.total === 1 && r.data.items[0].category === "Node");
  r = await j("GET", "/courses/search?sort=price-asc");
  ok("sort price asc", Number(r.data.items[0].price) === 30);
  r = await j("GET", "/courses/search?maxprice=60");
  ok("maxprice filter", r.data.total === 2);
  r = await j("GET", "/courses/search?level=advance");
  ok("level filter", r.data.total === 1);
  const cats = await j("GET", "/courses/categories");
  ok("categories distinct", Array.isArray(cats.data) && cats.data.length === 3);

  /* --- sections normalization --- */
  const one = await j("GET", `/course/${ids[0]}`);
  const c1 = one.data;
  ok("sections stored", c1.sections?.length === 1 && c1.sections[0].lessons.length === 1);
  ok("legacy milestoneList mirrored", c1.milestoneList?.[0]?.title === "L1");
  ok("lessons count auto-derived", c1.lessons === "1");

  /* --- reviews --- */
  const alphaId = ids[0]; // paid (50), authored by U
  const betaId = ids[1];

  // second user (not the author, not enrolled) must be blocked on paid course
  const { data: loginB } = await j("POST", "/user", { displayName: "B", email: "p2b@phase2.test", photoURL: "" });
  let rev = await j("POST", `/course/reviews/${alphaId}`, { rating: 5, comment: "x" }, loginB.token);
  ok("reviewing UN-enrolled paid course blocked", rev.status === 403);

  await j("POST", "/payment", { courseId: alphaId, price: "50", authorEmail: "x@x.com" }, t); // legit purchase by author-user
  rev = await j("POST", `/course/reviews/${alphaId}`, { rating: 5, comment: "<b>Great!</b>", name: U.displayName }, t);
  ok("enrolled user can review", rev.data?.acknowledged === true);

  const list = await j("GET", `/course/reviews/${alphaId}`);
  ok("review stored as plain text (tags stripped)", list.data.length === 1 && list.data[0].comment === "Great!" && !list.data[0].email);

  await j("POST", `/course/reviews/${alphaId}`, { rating: 3, comment: "Updated" }, t); // edit
  const updated = await j("GET", `/course/reviews/${alphaId}`);
  const aggCourse = (await j("GET", `/course/${alphaId}`)).data;
  ok("re-posting edits same review (upsert)", updated.data.length === 1 && updated.data[0].rating === 3);
  ok("rating aggregates on course", aggCourse.ratingAvg === 3 && aggCourse.ratingCount === 1);

  // free course reviewable without payment
  const freeAdd = await j("POST", "/course/add", { title: "Free Intro", price: "0", description: "<p>f</p>" }, t);
  const freeId = freeAdd.data.insertedId;
  const freRev = await j("POST", `/course/reviews/${freeId}`, { rating: 4, comment: "nice" }, t);
  ok("free course reviewable", freRev.data?.acknowledged === true);

  const del = await j("DELETE", `/course/reviews/${alphaId}`, null, t);
  const afterDel = (await j("GET", `/course/${alphaId}`)).data;
  ok("delete own review recalculates", del.data.deletedCount === 1 && afterDel.ratingCount === 0 && afterDel.ratingAvg === 0);

  /* --- wishlist --- */
  const tog1 = await j("POST", `/wishlist/${betaId}`, null, t);
  ok("wishlist add", tog1.data?.wished === true);
  const wl = await j("GET", "/wishlist", null, t);
  ok("wishlist hydrates course docs", wl.data.length === 1 && wl.data[0]._id === betaId);
  const tog2 = await j("POST", `/wishlist/${betaId}`, null, t);
  ok("wishlist remove (toggle)", tog2.data?.wished === false);
  const st = await j("GET", "/wishlist/statuses", null, t);
  ok("statuses reflect empty wishlist", st.data.wishlist.length === 0);

  /* --- progress state (resume/last lesson) --- */
  await j("PATCH", `/progress/${U.email}`, { courseId: alphaId, lessons: ["0"], positions: { 0: 42 }, lastLesson: 0 }, t);
  const state = await j("GET", `/progress/state/${U.email}`, null, t);
  ok("positions saved for resume", state.data.positions[alphaId]?.["0"] === 42);
  ok("lastLesson saved for autoplay-next", state.data.lastLesson[alphaId] === 0);
  const legacyMap = await j("GET", `/progress/${U.email}`, null, t);
  ok("legacy progress shape intact", legacyMap.data[alphaId][0] === "0");

  /* cleanup */
  for (const id of [...ids, freeId]) await j("DELETE", `/course/delete/${id}`, null, t);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
};

run().catch((e) => { console.error(e); process.exit(1); });
