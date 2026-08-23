require("dotenv").config({ path: ".env.local" });
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");
const sanitizeHtml = require("sanitize-html");
const rateLimit = require("express-rate-limit");
const crypto = require("crypto");

let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
}

const app = express();
const port = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "secret";
// admins come from env
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || "")
  .split(",")
  .map((e) => e.trim().toLowerCase())
  .filter(Boolean);
const INSTRUCTOR_SHARE = Number(process.env.INSTRUCTOR_SHARE) > 0 ? Number(process.env.INSTRUCTOR_SHARE) : 0.7;

const allowedOrigins = (process.env.CLIENT_URL || "")
  .split(",")
  .map((o) => o.trim().replace(/https:https:/, "https:"))
  .filter(Boolean);

app.use(
  cors({
    origin(origin, cb) {
      cb(null, true); // permissive; tighten via CLIENT_URL when ready
    },
  })
);
app.use(express.json());

const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch((err) => {
    console.error(`[api] ${req.method} ${req.originalUrl}:`, err?.message);
    res.status(err?.statusCode || 500).send({ message: err?.message || "Server error" });
  });

function createToken(user) {
  return jwt.sign({ email: user.email, role: user.role || "student" }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

function verifyToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).send({ message: "Unauthorized" });
  }
  const token = authHeader.split(" ")[1];
  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err || !decoded?.email) {
      return res.status(401).send({ message: "Unauthorized" });
    }
    req.user = decoded.email;
    req.role = decoded.role || "student";
    next();
  });
}

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.role)) {
    return res.status(403).send({ message: "Forbidden" });
  }
  next();
};

const requireSelfOrAdmin = (req, res, next) => {
  if (req.role !== "admin" && req.params.email !== req.user) {
    return res.status(403).send({ message: "Forbidden" });
  }
  next();
};

// rich text comes from instructors
const cleanDescription = (html) =>
  sanitizeHtml(String(html || ""), {
    allowedTags: [
      "p", "strong", "em", "u", "s", "br", "ul", "ol", "li",
      "h3", "h4", "blockquote", "a", "span",
    ],
    allowedAttributes: { a: ["href", "target", "rel"] },
    transformTags: {
      a: sanitizeHtml.simpleTransform("a", { rel: "noopener noreferrer nofollow" }),
    },
  });

function withSections(doc) {
  if (!Array.isArray(doc.sections)) return doc;
  doc.sections = doc.sections
    .map((s) => ({
      title: String(s?.title || "").slice(0, 140),
      lessons: (Array.isArray(s?.lessons) ? s.lessons : [])
        .filter((l) => l && l.title)
        .map((l) => ({
          title: String(l.title).slice(0, 180),
          videoUrl: String(l.videoUrl || ""),
        })),
    }))
    .filter((s) => s.title || s.lessons.length > 0);

  const flat = doc.sections.flatMap((s) => s.lessons);
  if (flat.length > 0) {
    doc.milestone = doc.sections[0]?.title || doc.milestone;
    doc.milestoneList = flat.map((l) => ({ title: l.title, videUrl: l.videoUrl }));
    doc.lessons = String(flat.length);
  }
  return doc;
}

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30, standardHeaders: true, legacyHeaders: false });
const paymentLimiter = rateLimit({ windowMs: 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

const toObjectId = (id) => {
  try {
    return new ObjectId(id);
  } catch {
    return null;
  }
};

const client = process.env.URI
  ? new MongoClient(process.env.URI, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    })
  : null;

let connectPromise = null;
function getConnectPromise() {
  if (!connectPromise) {
    if (!client) {
      return Promise.reject(
        Object.assign(new Error("Server not configured: missing URI env var"), { statusCode: 503 })
      );
    }
    connectPromise = client
      .connect()
      .then(async () => {
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
        // hot-path indexes (safe to re-run, allSettled so a bad legacy doc can't block boot)
        const { course, payment, review, user } = cols();
        await Promise.allSettled([
          course.createIndex({ category: 1 }),
          course.createIndex({ featured: -1, enrolled: -1 }),
          payment.createIndex({ customerEmail: 1 }),
          payment.createIndex({ authorEmail: 1 }),
          review.createIndex({ courseId: 1, email: 1 }, { unique: true }),
          user.createIndex({ email: 1 }, { unique: true }),
        ]);
      })
      .catch((err) => {
        console.error("MongoDB connection failed:", err?.message);
        connectPromise = null; // allow retry on next request
        throw Object.assign(new Error("Database unavailable"), { statusCode: 503 });
      });
  }
  return connectPromise;
}

getConnectPromise().catch(() => {});

function cols() {
  const database = client.db(process.env.DB_NAME || "devdeive_course");
  return {
    course: database.collection("course"),
    user: database.collection("user"),
    payment: database.collection("payment"),
    review: database.collection("review"),
    quiz: database.collection("quiz"),
    question: database.collection("question"),
    certificate: database.collection("certificate"),
    quizAttempt: database.collection("quizAttempt"),
    coupon: database.collection("coupon"),
  };
}

function lessonCount(doc) {
  if (Array.isArray(doc?.sections) && doc.sections.length > 0) {
    return doc.sections.reduce((n, s) => n + (s.lessons?.length || 0), 0);
  }
  if (Array.isArray(doc?.milestoneList)) {
    return doc.milestoneList.filter((l) => l && (l.title || l.videoTitleOne)).length;
  }
  return Number(doc?.lessons) || 0;
}

async function validateCoupon(couponCol, code) {
  if (!code) return null;
  const c = await couponCol.findOne({ code: String(code).toUpperCase() });
  if (!c) return null;
  if (c.expiresAt && new Date(c.expiresAt) < new Date()) return null;
  if (c.maxUses && (c.usedCount || 0) >= c.maxUses) return null;
  return c;
}

async function needDb() {
  await getConnectPromise();
  return cols();
}

// ---------------- course ----------------

app.get(
  "/course",
  wrap(async (req, res) => {
    const { course } = await needDb();
    res.send(await course.find().toArray());
  })
);

app.get(
  "/course/:id",
  wrap(async (req, res) => {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(404).send(null);
    const { course } = await needDb();
    res.send(await course.findOne({ _id }));
  })
);

app.post(
  "/course/add",
  verifyToken,
  wrap(async (req, res) => {
    const { user, course } = await needDb();
    const doc = { ...req.body };
    delete doc.role; // never trust client-supplied roles
    doc.description = cleanDescription(doc.description);
    doc.authorEmail = req.user; // ownership is derived from the token
    withSections(doc);
    res.send(await course.insertOne(doc));
    await user.updateOne(
      { email: req.user, role: { $in: [null, "student"] } },
      { $set: { role: "instructor" } }
    );
  })
);

app.delete(
  "/course/delete/:id",
  verifyToken,
  wrap(async (req, res) => {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(404).send({ deletedCount: 0 });
    const { course } = await needDb();
    const target = await course.findOne({ _id }, { projection: { authorEmail: 1 } });
    if (!target) return res.status(404).send({ deletedCount: 0 });
    if (req.role !== "admin" && target.authorEmail !== req.user) {
      return res.status(403).send({ message: "You can only delete your own courses" });
    }
    res.send(await course.deleteOne({ _id }));
  })
);

app.patch(
  "/course/edit/:id",
  verifyToken,
  wrap(async (req, res) => {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(404).send({ matchedCount: 0 });
    const { course } = await needDb();
    const target = await course.findOne({ _id }, { projection: { authorEmail: 1 } });
    if (!target) return res.status(404).send({ matchedCount: 0 });
    if (req.role !== "admin" && target.authorEmail !== req.user) {
      return res.status(403).send({ message: "You can only edit your own courses" });
    }
    const updates = { ...req.body };
    delete updates.role;
    if ("description" in updates) updates.description = cleanDescription(updates.description);
    withSections(updates);
    res.send(await course.updateOne({ _id }, { $set: updates }));
  })
);

app.get(
  "/course/find/:email",
  verifyToken,
  requireSelfOrAdmin,
  wrap(async (req, res) => {
    const { course } = await needDb();
    res.send(await course.find({ authorEmail: req.params.email }).toArray());
  })
);

app.get(
  "/course/access/:id",
  verifyToken,
  wrap(async (req, res) => {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(404).send({ allowed: false });
    const { course, payment } = await needDb();
    const target = await course.findOne(
      { _id },
      { projection: { price: 1, authorEmail: 1 } }
    );
    if (!target) return res.status(404).send({ allowed: false });
    const free = !target.price || Number(target.price) <= 0;
    const owns = target.authorEmail === req.user || req.role === "admin";
    const paid =
      (await payment.findOne(
        { courseId: req.params.id, customerEmail: req.user },
        { projection: { _id: 1 } }
      )) !== null;
    res.send({ allowed: free || owns || paid });
  })
);

// catalog search

app.get(
  "/courses/search",
  wrap(async (req, res) => {
    const { course } = await needDb();
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(48, Math.max(1, parseInt(req.query.limit, 10) || 9));

    const filter = {};
    if (req.query.q) {
      const rx = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      filter.$or = [{ title: rx }, { author: rx }, { category: rx }];
    }
    if (req.query.category && req.query.category !== "All") {
      filter.category = req.query.category;
    }
    if (req.query.level) filter.lave = req.query.level;
    const maxPrice = Number(req.query.maxprice);
    if (Number.isFinite(maxPrice) && maxPrice >= 0) {
      /* $convert with onError survives messy legacy price values */
      const toDouble = { $convert: { input: { $ifNull: ["$price", "0"] }, to: "double", onError: 0 } };
      filter.$and = [...(filter.$and || []), { $expr: { $lte: [toDouble, maxPrice] } }];
    }

    const sorts = {
      "price-asc": { price: 1 },
      "price-desc": { price: -1 },
      newest: { _id: -1 },
      popular: { enrolled: -1 },
      rating: { ratingAvg: -1, ratingCount: -1 },
      featured: { featured: -1, enrolled: -1 },
    };
    const sort = sorts[req.query.sort] || sorts.featured;
    const [items, total] = await Promise.all([
      course.find(filter).sort(sort).skip((page - 1) * limit).limit(limit).toArray(),
      course.countDocuments(filter),
    ]);

    res.send({ items, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
  })
);

app.get(
  "/courses/categories",
  wrap(async (req, res) => {
    const { course } = await needDb();
    const cats = await course
      .aggregate([{ $match: { category: { $nin: [null, ""] } } }, { $group: { _id: "$category" } }, { $sort: { _id: 1 } }])
      .toArray();
    res.send(cats.map((c) => c._id));
  })
);

// ---------------- reviews ----------------

async function refreshCourseRating(reviewCol, courseCol, courseIdStr, _idObj) {
  const [stats] = await reviewCol
    .aggregate([
      { $match: { courseId: courseIdStr } },
      { $group: { _id: "$courseId", avg: { $avg: "$rating" }, count: { $sum: 1 } } },
    ])
    .toArray();
  await courseCol.updateOne(
    { _id: _idObj },
    {
      $set: {
        ratingAvg: stats ? Math.round(stats.avg * 10) / 10 : 0,
        ratingCount: stats ? stats.count : 0,
      },
    }
  );
}

app.get(
  "/course/reviews/:id",
  wrap(async (req, res) => {
    const { review } = await needDb();
    const list = await review
      .find({ courseId: req.params.id }, { projection: { email: 0 } })
      .sort({ _id: -1 })
      .toArray();

    const authHeader = req.headers.authorization;
    if (authHeader?.startsWith("Bearer ")) {
      try {
        const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
        const mineId = (
          await review.findOne(
            { courseId: req.params.id, email: decoded.email },
            { projection: { _id: 1 } }
          )
        )?._id?.toString();
        if (mineId) {
          for (const r of list) if (r._id.toString() === mineId) r.mine = true;
        }
      } catch {
        /* invalid/expired token → no marker, list stays public */
      }
    }
    res.send(list);
  })
);

app.post(
  "/course/reviews/:id",
  verifyToken,
  wrap(async (req, res) => {
    const rating = Number(req.body?.rating);
    const comment = String(req.body?.comment || "").slice(0, 1200);
    if (!Number.isFinite(rating) || rating < 1 || rating > 5) {
      return res.status(400).send({ message: "Rating must be 1–5" });
    }
    const { course, payment, review } = await needDb();
    const target = await course.findOne(
      { _id: toObjectId(req.params.id) },
      { projection: { price: 1, authorEmail: 1 } }
    );
    if (!target) return res.status(404).send({ message: "Course not found" });

    const owns = target.authorEmail === req.user || req.role === "admin";
    const paid =
      (await payment.findOne(
        { courseId: req.params.id, customerEmail: req.user },
        { projection: { _id: 1 } }
      )) !== null;
    const free = !target.price || Number(target.price) <= 0;
    if (!owns && !paid && !free) {
      return res.status(403).send({ message: "Only enrolled learners can review" });
    }

    await review.updateOne(
      { courseId: req.params.id, email: req.user },
      {
        $set: {
          rating,
          comment: cleanDescription(comment).replace(/<[^>]*>/g, ""), // plain text only
          name: req.body?.name || "Learner",
          photo: req.body?.photo || "",
          updatedAt: new Date(),
        },
        $setOnInsert: { courseId: req.params.id, email: req.user, createdAt: new Date() },
      },
      { upsert: true }
    );
    await refreshCourseRating(review, course, req.params.id, toObjectId(req.params.id));
    res.send({ acknowledged: true });
  })
);

app.delete(
  "/course/reviews/:id",
  verifyToken,
  wrap(async (req, res) => {
    const { course, review } = await needDb();
    const result = await review.deleteOne({ courseId: req.params.id, email: req.user });
    await refreshCourseRating(review, course, req.params.id, toObjectId(req.params.id));
    res.send(result);
  })
);

// ---------------- wishlist ----------------

app.get(
  "/wishlist",
  verifyToken,
  wrap(async (req, res) => {
    const { user, course } = await needDb();
    const me = await user.findOne({ email: req.user }, { projection: { wishlist: 1 } });
    const ids = (me?.wishlist || [])
      .map((cid) => toObjectId(cid))
      .filter(Boolean);
    if (!ids.length) return res.send([]);
    res.send(await course.find({ _id: { $in: ids } }).toArray());
  })
);

app.post(
  "/wishlist/:courseId",
  verifyToken,
  wrap(async (req, res) => {
    const { user, course } = await needDb();
    const cid = req.params.courseId;
    if (!toObjectId(cid)) return res.status(404).send({ message: "Course not found" });
    const exists = await course.findOne({ _id: toObjectId(cid) }, { projection: { _id: 1 } });
    if (!exists) return res.status(404).send({ message: "Course not found" });

    const me = await user.findOne({ email: req.user }, { projection: { wishlist: 1 } });
    const current = Array.isArray(me?.wishlist) ? me.wishlist : [];
    const wished = current.includes(cid);
    await user.updateOne(
      { email: req.user },
      wished
        ? { $pull: { wishlist: cid } }
        : { $addToSet: { wishlist: cid } }
    );
    res.send({ wished: !wished });
  })
);

app.get(
  "/wishlist/statuses",
  verifyToken,
  wrap(async (req, res) => {
    const { user } = await needDb();
    const me = await user.findOne({ email: req.user }, { projection: { wishlist: 1 } });
    res.send({ wishlist: me?.wishlist || [] });
  })
);



async function canLearn(courseCol, paymentCol, courseDoc, email, role) {
  if (!courseDoc) return false;
  if (role === "admin" || courseDoc.authorEmail === email) return true;
  const price = Number(courseDoc.price);
  if (!price || price <= 0) return true;
  return (
    (await paymentCol.findOne(
      { courseId: courseDoc._id.toString(), customerEmail: email },
      { projection: { _id: 1 } }
    )) !== null
  );
}

// quizzes

const sanitizeQuiz = (body) => {
  const qs = Array.isArray(body?.questions) ? body.questions.slice(0, 20) : [];
  return {
    questions: qs
      .map((q) => {
        const options = (Array.isArray(q?.options) ? q.options : [])
          .slice(0, 6)
          .map((o) => String(o || "").slice(0, 200));
        const answerIdx = Number(q?.answerIdx);
        return options.length >= 2 && Number.isInteger(answerIdx) && answerIdx >= 0 && answerIdx < options.length && String(q?.q || "").trim()
          ? { q: String(q.q).slice(0, 400), options, answerIdx }
          : null;
      })
      .filter(Boolean),
    passScore: Math.min(100, Math.max(1, Number(body?.passScore) || 70)),
  };
};

app.get(
  "/quiz/:courseId",
  wrap(async (req, res) => {
    const { quiz } = await needDb();
    const doc = await quiz.findOne({ courseId: req.params.courseId });
    if (!doc) return res.send(null);

    const authHeader = req.headers.authorization;
    let isOwner = false;
    let email = null;
    let role = "student";
    if (authHeader?.startsWith("Bearer ")) {
      try {
        const decoded = jwt.verify(authHeader.split(" ")[1], JWT_SECRET);
        email = decoded.email;
        role = decoded.role || "student";
        const { course } = await needDb();
        const target = await course.findOne(
          { _id: toObjectId(req.params.courseId) },
          { projection: { authorEmail: 1 } }
        );
        isOwner = !!target && (target.authorEmail === email || role === "admin");
      } catch {
        /* anonymous */
      }
    }

    const payload = { courseId: doc.courseId, passScore: doc.passScore, questions: doc.questions };
    if (!isOwner) {
      // strip the answer key from learner copies
      payload.questions = doc.questions.map(({ q, options }) => ({ q, options }));
    }
    res.send(payload);
  })
);

app.put(
  "/quiz/:courseId",
  verifyToken,
  wrap(async (req, res) => {
    const { course, quiz } = await needDb();
    const target = await course.findOne(
      { _id: toObjectId(req.params.courseId) },
      { projection: { authorEmail: 1 } }
    );
    if (!target) return res.status(404).send({ message: "Course not found" });
    if (req.role !== "admin" && target.authorEmail !== req.user) {
      return res.status(403).send({ message: "You can only manage your own course quiz" });
    }
    const clean = sanitizeQuiz(req.body);
    if (clean.questions.length === 0) {
      // empty payload = remove the quiz entirely
      await quiz.deleteOne({ courseId: req.params.courseId });
      return res.send({ removed: true });
    }
    await quiz.updateOne(
      { courseId: req.params.courseId },
      { $set: { ...clean, updatedAt: new Date() }, $setOnInsert: { courseId: req.params.courseId } },
      { upsert: true }
    );
    res.send({ acknowledged: true, count: clean.questions.length });
  })
);

app.post(
  "/quiz/:courseId/attempt",
  verifyToken,
  wrap(async (req, res) => {
    const { course, quiz, payment, quizAttempt } = await needDb();
    const target = await course.findOne({ _id: toObjectId(req.params.courseId) });
    if (!target) return res.status(404).send({ message: "Course not found" });

    const allowed = await canLearn(course, payment, target, req.user, req.role);
    if (!allowed) return res.status(403).send({ message: "Enroll first" });

    const doc = await quiz.findOne({ courseId: req.params.courseId });
    if (!doc) return res.status(404).send({ message: "No quiz for this course" });

    const answers = Array.isArray(req.body?.answers) ? req.body.answers : [];
    let correct = 0;
    const review = doc.questions.map((q, i) => {
      const given = Number(answers[i]);
      const right = given === q.answerIdx;
      if (right) correct++;
      return {
        q: q.q,
        options: q.options,
        chosen: Number.isInteger(given) ? given : -1,
        answerIdx: q.answerIdx,
        correct: right,
      };
    });
    const total = doc.questions.length;
    const score = total > 0 ? Math.round((correct / total) * 100) : 0;
    const passed = score >= doc.passScore;

    await quizAttempt.insertOne({
      courseId: req.params.courseId,
      email: req.user,
      score,
      correct,
      total,
      passed,
      at: new Date(),
    });

    res.send({ score, correct, total, passed, passScore: doc.passScore, review });
  })
);

app.get(
  "/quiz/:courseId/attempts/me",
  verifyToken,
  wrap(async (req, res) => {
    const { quizAttempt } = await needDb();
    const latest = await quizAttempt
      .find({ courseId: req.params.courseId, email: req.user })
      .sort({ at: -1 })
      .limit(1)
      .toArray();
    res.send(latest[0] || null);
  })
);

// ---------------- certificates ----------------

const certCode = () =>
  "AVN-" + crypto.randomBytes(4).toString("hex").toUpperCase();

app.post(
  "/certificates/:courseId",
  loginLimiter,
  verifyToken,
  wrap(async (req, res) => {
    const { course, payment, quiz, quizAttempt, certificate, user: userCol } = await needDb();
    const target = await course.findOne({ _id: toObjectId(req.params.courseId) });
    if (!target) return res.status(404).send({ message: "Course not found" });

    const allowed = await canLearn(course, payment, target, req.user, req.role);
    if (!allowed) return res.status(403).send({ message: "Enroll and finish the course first" });

    const learner = await userCol.findOne({ email: req.user }, { projection: { displayName: 1, progress: 1 } });
    const done = new Set(learner?.progress?.[req.params.courseId] || []);
    const totalLessons = lessonCount(target);
    if (totalLessons > 0 && done.size < totalLessons) {
      return res.status(403).send({
        message: `Finish all lessons first (${done.size}/${totalLessons})`,
      });
    }

    const hasQuiz = (await quiz.findOne({ courseId: req.params.courseId }, { projection: { _id: 1 } })) !== null;
    if (hasQuiz) {
      const attempt = await quizAttempt
        .findOne({ courseId: req.params.courseId, email: req.user }, { sort: { at: -1 } });
      if (!attempt || !attempt.passed) {
        return res.status(403).send({ message: "Pass the course quiz to unlock your certificate" });
      }
    }

    const existing = await certificate.findOne({ courseId: req.params.courseId, email: req.user });
    if (existing) return res.send(existing);

    const doc = {
      code: certCode(),
      courseId: req.params.courseId,
      email: req.user,
      studentName: learner?.displayName || "Avenor Learner",
      courseTitle: target.title,
      authorName: target.author || "",
      issuedAt: new Date(),
    };
    await certificate.insertOne(doc);
    res.send(doc);
  })
);

app.get(
  "/certificates/mine",
  verifyToken,
  wrap(async (req, res) => {
    const { certificate } = await needDb();
    res.send(await certificate.find({ email: req.user }).sort({ issuedAt: -1 }).toArray());
  })
);

app.get(
  "/certificates/verify/:code",
  wrap(async (req, res) => {
    const { certificate } = await needDb();
    const doc = await certificate.findOne(
      { code: String(req.params.code || "").toUpperCase() },
      { projection: { _id: 0, email: 0 } }
    );
    if (!doc) return res.status(404).send({ valid: false });
    res.send({ valid: true, ...doc });
  })
);

// ---------------- Q&A ----------------

const plainText = (s) =>
  sanitizeHtml(String(s || ""), { allowedTags: [], allowedAttributes: {} }).slice(0, 1500).trim();

app.get(
  "/questions/:courseId",
  wrap(async (req, res) => {
    const { question } = await needDb();
    res.send(await question.find({ courseId: req.params.courseId }).sort({ createdAt: -1 }).limit(100).toArray());
  })
);

app.post(
  "/questions/:courseId",
  verifyToken,
  wrap(async (req, res) => {
    const text = plainText(req.body?.text);
    if (!text) return res.status(400).send({ message: "Question text required" });
    const { course, payment, question } = await needDb();
    const target = await course.findOne(
      { _id: toObjectId(req.params.courseId) },
      { projection: { price: 1, authorEmail: 1, author: 1 } }
    );
    if (!target) return res.status(404).send({ message: "Course not found" });
    const allowed = await canLearn(course, payment, target, req.user, req.role);
    if (!allowed) return res.status(403).send({ message: "Enroll to join the discussion" });

    const lessonId = Number(req.body?.lessonId);
    const result = await question.insertOne({
      courseId: req.params.courseId,
      lessonId: Number.isInteger(lessonId) && lessonId >= 0 ? lessonId : -1,
      email: req.user,
      name: req.body?.name || "Learner",
      photo: req.body?.photo || "",
      text,
      isAuthor: target.authorEmail === req.user,
      replies: [],
      createdAt: new Date(),
    });
    res.send(result);
  })
);

app.post(
  "/questions/:questionId/reply",
  verifyToken,
  wrap(async (req, res) => {
    const text = plainText(req.body?.text);
    if (!text) return res.status(400).send({ message: "Reply text required" });
    const { course, payment, question } = await needDb();
    const q = await question.findOne(
      { _id: toObjectId(req.params.questionId) },
      { projection: { courseId: 1 } }
    );
    if (!q) return res.status(404).send({ message: "Question not found" });

    const target = await course.findOne(
      { _id: toObjectId(q.courseId) },
      { projection: { price: 1, authorEmail: 1 } }
    );
    const allowed = target ? await canLearn(course, payment, target, req.user, req.role) : false;
    if (!allowed) return res.status(403).send({ message: "Enroll to join the discussion" });

    const isInstructor = !!target && target.authorEmail === req.user;
    const result = await question.updateOne(
      { _id: q._id },
      {
        $push: {
          replies: {
            name: req.body?.name || "Learner",
            photo: req.body?.photo || "",
            text,
            isInstructor,
            at: new Date(),
          },
        },
      }
    );
    res.send(result);
  })
);

app.delete(
  "/questions/:id",
  verifyToken,
  wrap(async (req, res) => {
    const { question } = await needDb();
    const filter = { _id: toObjectId(req.params.id) };
    if (!filter._id) return res.status(404).send({ deletedCount: 0 });
    if (req.role !== "admin") filter.email = req.user;
    res.send(await question.deleteOne(filter));
  })
);

// notes

app.get(
  "/notes/:courseId",
  verifyToken,
  wrap(async (req, res) => {
    const { user: userCol } = await needDb();
    const me = await userCol.findOne(
      { email: req.user },
      { projection: { [`notes.${req.params.courseId}`]: 1 } }
    );
    res.send(me?.notes?.[req.params.courseId] || []);
  })
);

app.patch(
  "/notes/:courseId",
  verifyToken,
  wrap(async (req, res) => {
    const raw = Array.isArray(req.body?.notes) ? req.body.notes.slice(0, 100) : [];
    const notes = raw.map((n) => ({
      lessonId: Math.max(0, Number(n?.lessonId) || 0),
      at: Math.max(0, Math.floor(Number(n?.at) || 0)),
      text: plainText(n?.text),
    }));
    const { user: userCol } = await needDb();
    const result = await userCol.updateOne(
      { email: req.user },
      { $set: { [`notes.${req.params.courseId}`]: notes } },
      { upsert: true }
    );
    res.send(result);
  })
);

// ---------------- coupons ----------------

app.get(
  "/coupons/validate/:code",
  wrap(async (req, res) => {
    const { coupon } = await needDb();
    const c = await validateCoupon(coupon, req.params.code);
    if (!c) return res.status(404).send({ valid: false, message: "Invalid or expired coupon" });
    res.send({ valid: true, code: c.code, percentOff: c.percentOff });
  })
);

// ---------------- admin ----------------

app.get(
  "/admin/stats",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    const { course, payment, user } = await needDb();
    const [users, courses, paidAgg] = await Promise.all([
      user.countDocuments(),
      course.countDocuments(),
      payment
        .aggregate([
          {
            $group: {
              _id: null,
              gross: { $sum: { $convert: { input: { $ifNull: ["$price", "0"] }, to: "double", onError: 0 } } },
              instructorDue: { $sum: { $ifNull: ["$instructorShare", { $multiply: [{ $convert: { input: { $ifNull: ["$price", "0"] }, to: "double", onError: 0 } }, INSTRUCTOR_SHARE] }] } },
              count: { $sum: 1 },
            },
          },
        ])
        .toArray(),
    ]);
    const latestUsers = await user
      .find({}, { projection: { displayName: 1, email: 1, role: 1, banned: 1 } })
      .sort({ _id: -1 })
      .limit(5)
      .toArray();
    res.send({
      users,
      courses,
      sales: paidAgg[0]?.count || 0,
      grossRevenue: Math.round((paidAgg[0]?.gross || 0) * 100) / 100,
      instructorDue: Math.round((paidAgg[0]?.instructorDue || 0) * 100) / 100,
      platformRevenue:
        Math.round(((paidAgg[0]?.gross || 0) - (paidAgg[0]?.instructorDue || 0)) * 100) / 100,
      latestUsers,
    });
  })
);

app.get(
  "/admin/users",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    const page = Math.max(1, parseInt(req.query.page, 10) || 1);
    const limit = Math.min(50, parseInt(req.query.limit, 10) || 20);
    const filter = {};
    if (req.query.q) {
      const rx = new RegExp(req.query.q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
      filter.$or = [{ email: rx }, { displayName: rx }];
    }
    const { user } = await needDb();
    const [items, total] = await Promise.all([
      user
        .find(filter, {
          projection: { email: 1, displayName: 1, photoURL: 1, role: 1, banned: 1 },
        })
        .sort({ _id: -1 })
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray(),
      user.countDocuments(filter),
    ]);
    res.send({ items, total, page, pages: Math.max(1, Math.ceil(total / limit)) });
  })
);

app.patch(
  "/admin/users/:email",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    if (req.params.email === req.user) {
      return res.status(400).send({ message: "You cannot modify your own account here" });
    }
    const updates = {};
    if (req.body?.role !== undefined) {
      if (!["student", "instructor", "admin"].includes(req.body.role)) {
        return res.status(400).send({ message: "Invalid role" });
      }
      updates.role = req.body.role;
    }
    if (req.body?.banned !== undefined) updates.banned = !!req.body.banned;
    if (Object.keys(updates).length === 0) {
      return res.status(400).send({ message: "Nothing to update" });
    }
    const { user } = await needDb();
    res.send(await user.updateOne({ email: req.params.email }, { $set: updates }));
  })
);

app.patch(
  "/admin/courses/:id/featured",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    const { course } = await needDb();
    const featured = !!req.body?.featured;
    res.send(
      await course.updateOne({ _id: toObjectId(req.params.id) }, { $set: { featured } })
    );
  })
);

app.get(
  "/admin/coupons",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    const { coupon } = await needDb();
    res.send(await coupon.find().sort({ _id: -1 }).limit(100).toArray());
  })
);

app.post(
  "/admin/coupons",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    const code = String(req.body?.code || "").toUpperCase().replace(/[^A-Z0-9_-]/g, "");
    const percentOff = Number(req.body?.percentOff);
    if (!code || !Number.isFinite(percentOff) || percentOff < 1 || percentOff > 100) {
      return res.status(400).send({ message: "Code and percentOff (1–100) required" });
    }
    const maxUses = Number(req.body?.maxUses);
    const doc = {
      code,
      percentOff: Math.round(percentOff),
      maxUses: Number.isFinite(maxUses) && maxUses > 0 ? maxUses : null,
      expiresAt: req.body?.expiresAt ? new Date(req.body.expiresAt) : null,
      usedCount: 0,
    };
    const { coupon } = await needDb();
    const exists = await coupon.findOne({ code });
    if (exists) return res.status(409).send({ message: "Coupon code already exists" });
    const result = await coupon.insertOne(doc);
    res.send({ acknowledged: true, insertedId: result.insertedId });
  })
);

app.delete(
  "/admin/coupons/:code",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    const { coupon } = await needDb();
    res.send(await coupon.deleteOne({ code: String(req.params.code).toUpperCase() }));
  })
);

// ---------------- instructor analytics (self-scoped) ----------------

app.get(
  "/analytics/instructor",
  verifyToken,
  wrap(async (req, res) => {
    const { payment, course, review } = await needDb();

    const sales = await payment.find({ authorEmail: req.user }).toArray();
    const revenue = sales.reduce(
      (sum, s) =>
        sum +
        (Number(s.instructorShare) ||
          (Number(s.price) || 0) * INSTRUCTOR_SHARE),
      0
    );

    const myCourses = await course
      .find({ authorEmail: req.user }, { projection: { title: 1, enrolled: 1, price: 1, ratingAvg: 1, ratingCount: 1, featured: 1 } })
      .toArray();

    const byCourse = myCourses.map((c) => {
      const mine = sales.filter((s) => s.courseId === c._id.toString());
      const courseRevenue = mine.reduce(
        (sum, s) =>
          sum + (Number(s.instructorShare) || (Number(s.price) || 0) * INSTRUCTOR_SHARE),
        0
      );
      return {
        courseId: c._id,
        title: c.title,
        enrolled: c.enrolled || 0,
        paidSales: mine.length,
        revenue: Math.round(courseRevenue * 100) / 100,
        ratingAvg: c.ratingAvg || 0,
        ratingCount: c.ratingCount || 0,
        featured: !!c.featured,
        price: c.price || "0",
      };
    });

    const ids = myCourses.map((c) => c._id.toString());
    const recentReviews =
      ids.length > 0
        ? await review
            .find({ courseId: { $in: ids } }, { projection: { email: 0 } })
            .sort({ _id: -1 })
            .limit(8)
            .toArray()
        : [];

    const students = sales
      .slice()
      .sort((a, b) => new Date(b.createdAt || b._id.generatedAt || 0) - new Date(a.createdAt || a._id.generatedAt || 0))
      .slice(0, 10)
      .map((s) => ({
        name: s.customerName || s.customerEmail,
        title: s.title,
        amount: s.finalPrice || s.price,
        at: s.createdAt || null,
      }));

    res.send({
      totals: {
        revenue: Math.round(revenue * 100) / 100,
        paidSales: sales.length,
        enrolledTotal: byCourse.reduce((n, c) => n + c.enrolled, 0),
        courses: myCourses.length,
      },
      byCourse,
      recentReviews,
      students,
    });
  })
);

// ---------------- user ----------------

app.get(
  "/user",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    const { user } = await needDb();
    res.send(
      await user
        .find({}, { projection: { progress: 0 } })
        .toArray()
    );
  })
);

app.get(
  "/users/me",
  verifyToken,
  wrap(async (req, res) => {
    const { user } = await needDb();
    res.send(await user.findOne({ email: req.user }, { projection: { progress: 0 } }));
  })
);

app.post(
  "/user",
  loginLimiter,
  wrap(async (req, res) => {
    const { user } = await needDb();
    const data = { ...req.body };
    delete data.role; // roles are server-assigned only
    const itUserExist = await user.findOne({ email: data?.email });
    if (itUserExist?._id) {
      if (itUserExist.banned) {
        return res.status(403).send({ message: "This account has been suspended." });
      }
        if (ADMIN_EMAILS.includes(String(data.email).toLowerCase()) && itUserExist.role !== "admin") {
        await user.updateOne({ email: data.email }, { $set: { role: "admin" } });
        itUserExist.role = "admin";
      }
      return res.send({ token: createToken(itUserExist) });
    }
    const role = ADMIN_EMAILS.includes(String(data.email).toLowerCase()) ? "admin" : "student";
    const inserted = await user.insertOne({ ...data, role });
    res.send({
      token: createToken({ email: data.email, role, _id: inserted.insertedId }),
    });
  })
);

app.get(
  "/user/:email",
  verifyToken,
  requireSelfOrAdmin,
  wrap(async (req, res) => {
    const { user } = await needDb();
    res.send(await user.findOne({ email: req.params.email }, { projection: { progress: 0 } }));
  })
);

app.patch(
  "/user/:email",
  verifyToken,
  requireSelfOrAdmin,
  wrap(async (req, res) => {
    const { user } = await needDb();
    const updates = { ...req.body };
    delete updates.role; // role changes require an admin route
    delete updates.enrolledCourses; // enrollment is derived from payments
    res.send(
      await user.updateOne(
        { email: req.params.email },
        { $set: updates },
        { upsert: true }
      )
    );
  })
);

// ---------------- payment ----------------

app.get(
  "/payment",
  verifyToken,
  requireRole("admin"),
  wrap(async (req, res) => {
    const { payment } = await needDb();
    res.send(await payment.find().toArray());
  })
);

app.get(
  "/payments/me",
  verifyToken,
  wrap(async (req, res) => {
    const { payment } = await needDb();
    res.send(
      await payment
        .find({ $or: [{ customerEmail: req.user }, { authorEmail: req.user }] })
        .toArray()
    );
  })
);

app.post(
  "/create-payment-intent",
  paymentLimiter,
  wrap(async (req, res) => {
    if (!stripe) {
      return res.status(502).send({
        message:
          "Payment gateway is not configured (missing STRIPE_SECRET_KEY).",
      });
    }

    let courseDoc = null;
    const courseId = req.body?.courseId;
    if (courseId) {
      const { course } = await needDb();
      courseDoc = await course.findOne(
        { _id: toObjectId(courseId) },
        { projection: { price: 1 } }
      );
      if (!courseDoc) return res.status(404).send({ message: "Course not found" });
    }
    const basePrice = courseDoc
      ? Number(courseDoc.price) || 0
      : Number(req.body?.price);
    if (!Number.isFinite(basePrice) || basePrice <= 0) {
      return res.status(400).send({ message: "Invalid price" });
    }

    const { coupon: couponCol } = await needDb();
    const coupon = await validateCoupon(couponCol, req.body?.couponCode);
    const percentOff = coupon ? Math.min(100, Math.max(1, Number(coupon.percentOff) || 0)) : 0;
    const finalPrice = Math.max(0, basePrice * (1 - percentOff / 100));

    try {
      const amount = Math.max(50, Math.round(finalPrice * 100)); // Stripe minimum 50¢
      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        payment_method_types: ["card"],
        metadata: { courseId: String(courseId || ""), couponCode: coupon?.code || "" },
      });
      res.send({
        clientSecret: paymentIntent.client_secret,
        originalPrice: basePrice,
        finalPrice: amount / 100,
        discount: percentOff,
        couponCode: coupon?.code || null,
        intentAmount: amount,
      });
    } catch (stripeErr) {
      console.error("[stripe] create-payment-intent:", stripeErr.message);
      res
        .status(stripeErr.type === "StripeAuthenticationError" ? 502 : 400)
        .send({
          message:
            stripeErr.type === "StripeAuthenticationError"
              ? "Payment gateway is not configured (invalid STRIPE_SECRET_KEY)."
              : stripeErr.message,
        });
    }
  })
);

app.post(
  "/payment",
  verifyToken,
  wrap(async (req, res) => {
    const { payment, course, user, coupon: couponCol } = await needDb();
    const data = { ...req.body };
    data.customerEmail = req.user;

    let basePrice = Number(data.price) || 0;
    const courseDoc = data.courseId
      ? await course.findOne({ _id: toObjectId(data.courseId) }, { projection: { price: 1 } })
      : null;
    if (courseDoc) basePrice = Number(courseDoc.price) || basePrice;

    const coupon = await validateCoupon(couponCol, data.couponCode);
    const percentOff = coupon ? Math.min(100, Math.max(1, Number(coupon.percentOff) || 0)) : 0;
    const expectedFinal = basePrice * (1 - percentOff / 100);

    if (stripe && data.transactionId) {
      try {
        const intent = await stripe.paymentIntents.retrieve(data.transactionId);
        if (intent.status !== "succeeded") {
          return res.status(402).send({ message: "Payment not completed" });
        }
            if (Math.abs(intent.amount - Math.round(expectedFinal * 100)) > 1) {
          return res.status(402).send({ message: "Payment amount mismatch" });
        }
      } catch (err) {
        console.error("[stripe] intent verification failed:", err.message);
        return res.status(402).send({ message: "Could not verify payment" });
      }
    }

    data.finalPrice = Math.round(expectedFinal * 100) / 100;
    data.discount = percentOff;
    data.instructorShare = Math.round(expectedFinal * INSTRUCTOR_SHARE * 100) / 100;
    data.platformFee = Math.round((expectedFinal - data.instructorShare) * 100) / 100;

    const result = await payment.insertOne(data);

    if (coupon) {
      await couponCol.updateOne(
        { _id: coupon._id },
        { $inc: { usedCount: 1 } }
      );
    }

    const _id = toObjectId(data.courseId);
    if (_id) {
      const paidCourse = await course.findOne({ _id });
      if (!paidCourse) return res.send(result);
      const enrolledTotal = (paidCourse?.enrolled || 0) + 1;
      await course.updateOne({ _id }, { $set: { enrolled: enrolledTotal } });

      const customer = await user.findOne({ email: req.user });
      const enrolledCourses = Array.isArray(customer?.enrolledCourses)
        ? customer.enrolledCourses
        : [];
      if (!enrolledCourses.some((c) => c?._id === data.courseId)) {
        enrolledCourses.push(paidCourse);
      }
      await user.updateOne(
        { email: req.user },
        { $set: { enrolledCourses } },
        { upsert: true }
      );
    }

    res.send(result);
  })
);

// ---------------- lesson progress (LMS) ----------------

app.get(
  "/progress/:email",
  verifyToken,
  requireSelfOrAdmin,
  wrap(async (req, res) => {
    const { user } = await needDb();
    const result = await user.findOne(
      { email: req.params.email },
      { projection: { progress: 1 } }
    );
    res.send(result?.progress || {});
  })
);

app.get(
  "/progress/state/:email",
  verifyToken,
  requireSelfOrAdmin,
  wrap(async (req, res) => {
    const { user } = await needDb();
    const result = await user.findOne(
      { email: req.params.email },
      { projection: { progress: 1, progressPositions: 1, lastLesson: 1 } }
    );
    res.send({
      completed: result?.progress || {},
      positions: result?.progressPositions || {},
      lastLesson: result?.lastLesson || {},
    });
  })
);

app.patch(
  "/progress/:email",
  verifyToken,
  requireSelfOrAdmin,
  wrap(async (req, res) => {
    const { courseId, lessons, positions, lastLesson } = req.body || {};
    if (!courseId || !Array.isArray(lessons)) {
      return res
        .status(400)
        .send({ message: "courseId and lessons[] required" });
    }
    const set = { [`progress.${courseId}`]: lessons.map(String) };
    /* Resume playback + autoplay-next support */
    if (positions && typeof positions === "object" && !Array.isArray(positions)) {
      set[`progressPositions.${courseId}`] = positions;
    }
    if (Number.isFinite(Number(lastLesson))) {
      set[`lastLesson.${courseId}`] = Number(lastLesson);
    }
    const { user } = await needDb();
    await user.updateOne(
      { email: req.params.email },
      { $set: set },
      { upsert: true }
    );
    res.send({ acknowledged: true });
  })
);

// ---------------- misc ----------------

app.get(
  "/sitemap.xml",
  wrap(async (req, res) => {
    /* Prefer a public origin from CLIENT_URL; never emit localhost. */
    const candidates = (process.env.CLIENT_URL || "")
      .split(",")
      .map((o) => o.trim().replace(/\/+$/, ""))
      .filter(Boolean);
    const origin =
      candidates.find((o) => /^https:\/\//.test(o) && !/localhost|127\.0\.0\.1/.test(o)) ||
      `${req.protocol}://${req.get("host")}`;
    let courseUrls = "";
    try {
      const { course } = await needDb();
      const docs = await course
        .find({}, { projection: { _id: 1 } })
        .sort({ _id: -1 })
        .limit(2000)
        .toArray();
      courseUrls = docs
        .map((d) => `  <url><loc>${origin}/courses/${d._id}</loc></url>`)
        .join("\n");
    } catch {
      /* DB down → still emit static entries */
    }
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>${origin}/</loc></url>
  <url><loc>${origin}/courses</loc></url>
  <url><loc>${origin}/contact</loc></url>
${courseUrls}
</urlset>`;
    res.set("Content-Type", "application/xml").send(xml);
  })
);

app.get("/", (req, res) => {
  res.json({ status: "ok", service: "avenor-server" });
});

// Vercel serverless: export the app. Local/Render: keep the HTTP listener.
if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`Devdrive server listening on port ${port}`);
  });
}

module.exports = app;
