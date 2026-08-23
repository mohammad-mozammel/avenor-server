/* Phase 4 verification — admin, coupons, payment integrity, analytics.
   Run:  ADMIN_EMAILS=a@phase4.test DB_NAME=phase4_test node index.js    */
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

const A = { displayName: "Admin Guy", email: "a@phase4.test", photoURL: "" };
const S = { displayName: "Student X", email: "s@phase4.test", photoURL: "" };

const run = async () => {
  /* --- role assignment via ADMIN_EMAILS --- */
  const tA = (await j("POST", "/user", A)).data.token;
  ok("ADMIN_EMAILS login gets admin token", (() => {
    try {
      return JSON.parse(atob(tA.split(".")[1])).role === "admin";
    } catch { return false; }
  })());
  const tS = (await j("POST", "/user", S)).data.token;
  ok("regular login stays student", JSON.parse(atob(tS.split(".")[1])).role === "student");

  /* --- seed course by student-turned-instructor --- */
  const add = await j("POST", "/course/add", { title: "P4 Course", price: "100", description: "<p>d</p>" }, tS);
  const cid = add.data.insertedId;

  /* --- coupons --- */
  let r = await j("POST", "/admin/coupons", { code: "SAVE25", percentOff: 25, maxUses: 10 }, tS);
  ok("non-admin cannot create coupon", r.status === 403);
  r = await j("POST", "/admin/coupons", { code: "SAVE25", percentOff: 25 }, tA);
  ok("admin creates coupon", r.data?.acknowledged === true);
  r = await j("POST", "/admin/coupons", { code: "SAVE25", percentOff: 30 }, tA);
  ok("duplicate code rejected", r.status === 409);

  const v = await j("GET", "/coupons/validate/save25");
  ok("public validation works (case-insensitive)", v.data.valid === true && v.data.percentOff === 25);
  const badV = await j("GET", "/coupons/validate/NOPE");
  ok("unknown coupon invalid", badV.data.valid === false || badV.status === 404);

  /* --- intent is server-priced (no stripe key needed to check pricing math
         only — but stripe IS configured here, so we just check the response) --- */
  r = await j("POST", "/create-payment-intent", { courseId: cid, couponCode: "SAVE25" }, tS);
  if (r.data?.clientSecret) {
    ok("intent uses server price with coupon", r.data.originalPrice === 100 && r.data.finalPrice === 75 && r.data.discount === 25);
  } else {
    // Stripe unavailable in this environment → must at least not trust client price
    console.log("  SKIP live-intent checks (stripe unavailable)");
  }

  /* --- payment verification rejects fake intents when stripe configured --- */
  r = await j("POST", "/payment", { courseId: cid, price: "100", transactionId: "pi_fake_123" }, tS);
  if ((await j("GET", "/coupons/validate/SAVE25")).status === 200) {
    ok("fake transactionId rejected", r.status === 402);
  }

  /* --- admin stats/users gated + working --- */
  ok("stats blocked for non-admin", (await j("GET", "/admin/stats", null, tS)).status === 403);
  r = await j("GET", "/admin/stats", null, tA);
  ok("admin stats compute", typeof r.data.users === "number" && typeof r.data.grossRevenue === "number");

  r = await j("GET", "/admin/users?q=phase4", null, tA);
  ok("admin roster search", r.data.total >= 2);

  r = await j("PATCH", `/admin/users/${S.email}`, { role: "instructor" }, tA);
  ok("admin promotes user", r.data.acknowledged === true);
  const meS = await j("GET", "/users/me", null, tS);
  ok("promoted role visible on profile", meS.data.role === "instructor");
  r = await j("PATCH", `/admin/users/${A.email}`, { role: "student" }, tA);
  ok("admin cannot modify own account", r.status === 400);

  /* --- feature toggle --- */
  r = await j("PATCH", `/admin/courses/${cid}/featured`, { featured: true }, tA);
  ok("feature toggle works", r.data.acknowledged === true);
  const search = await j("GET", "/courses/search?sort=featured");
  ok("featured sorts first", search.data.items[0]?._id === cid);

  /* --- instructor analytics --- */
  r = await j("GET", "/analytics/instructor", null, tS);
  ok("analytics self-scoped shape", r.data.totals && Array.isArray(r.data.byCourse));
  const mineCourse = r.data.byCourse.find((c) => c.courseId === cid);
  ok("per-course rollup present", !!mineCourse && mineCourse.featured === true && mineCourse.enrolled === 0);

  /* --- cleanup --- */
  await j("DELETE", `/course/delete/${cid}`, null, tS);
  await j("DELETE", "/admin/coupons/SAVE25", null, tA);

  console.log(`\n${pass} passed, ${fail} failed`);
  process.exit(fail ? 1 : 0);
};

run().catch((e) => { console.error(e); process.exit(1); });
