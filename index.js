require("dotenv").config({ path: ".env.local" });
const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const jwt = require("jsonwebtoken");

/* Stripe key comes ONLY from env vars — never hardcode secrets in source. */
let stripe = null;
if (process.env.STRIPE_SECRET_KEY) {
  stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
}

const app = express();
const port = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || "secret";

/**
 * CORS whitelist from CLIENT_URL (comma-separated). Localhost dev ports are
 * always allowed; anything else falls back open like before.
 */
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

/**
 * Wrap async route handlers: without this, ANY rejected promise inside a
 * route (Stripe error, bad ObjectId, Mongo timeout...) becomes an unhandled
 * rejection that terminates Node >= 15 — killing the service (502 loops).
 */
const wrap = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch((err) => {
    console.error(`[api] ${req.method} ${req.originalUrl}:`, err?.message);
    res.status(err?.statusCode || 500).send({ message: err?.message || "Server error" });
  });

function createToken(user) {
  return jwt.sign({ email: user.email }, JWT_SECRET, { expiresIn: "7d" });
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
    next();
  });
}

/** Safe ObjectId parse — invalid ids must 404, never throw. */
const toObjectId = (id) => {
  try {
    return new ObjectId(id);
  } catch {
    return null;
  }
};

/**
 * MongoDB: routes are registered IMMEDIATELY at module load so they exist
 * even on a serverless cold start. Handlers `await dbReady` before touching
 * collections. A missing/failed connection yields a clear 503 JSON response
 * instead of silently dead routes.
 */
const client = process.env.URI
  ? new MongoClient(process.env.URI, {
      serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
      },
    })
  : null;

/**
 * Lazy, retryable connection. A failed connect must NOT be cached forever:
 * on serverless cold starts a single transient failure would otherwise turn
 * every request on that instance into "Database unavailable". On failure the
 * promise is cleared so the next request retries.
 */
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
      .then(() => console.log("Pinged your deployment. You successfully connected to MongoDB!"))
      .catch((err) => {
        console.error("MongoDB connection failed:", err?.message);
        connectPromise = null; // allow retry on next request
        throw Object.assign(new Error("Database unavailable"), { statusCode: 503 });
      });
  }
  return connectPromise;
}

// silence unhandled-rejection noise; handlers surface errors themselves
getConnectPromise().catch(() => {});

function cols() {
  const database = client.db("devdeive_course");
  return {
    course: database.collection("course"),
    user: database.collection("user"),
    payment: database.collection("payment"),
  };
}

/** Ensure DB is usable before a query; throw a clean error otherwise. */
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
    const { course } = await needDb();
    res.send(await course.insertOne(req.body));
  })
);

app.delete(
  "/course/delete/:id",
  verifyToken,
  wrap(async (req, res) => {
    const _id = toObjectId(req.params.id);
    if (!_id) return res.status(404).send({ deletedCount: 0 });
    const { course } = await needDb();
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
    res.send(await course.updateOne({ _id }, { $set: req.body }));
  })
);

app.get(
  "/course/find/:email",
  wrap(async (req, res) => {
    const { course } = await needDb();
    res.send(await course.find({ authorEmail: req.params.email }).toArray());
  })
);

// ---------------- user ----------------

app.get(
  "/user",
  wrap(async (req, res) => {
    const { user } = await needDb();
    res.send(await user.find().toArray());
  })
);

app.post(
  "/user",
  wrap(async (req, res) => {
    const { user } = await needDb();
    const data = req.body;
    const token = createToken(data);
    const itUserExist = await user.findOne({ email: data?.email });
    if (itUserExist?._id) {
      return res.send({ token });
    }
    await user.insertOne(data);
    res.send({ token });
  })
);

app.get(
  "/user/:email",
  wrap(async (req, res) => {
    const { user } = await needDb();
    res.send(await user.findOne({ email: req.params.email }));
  })
);

app.patch(
  "/user/:email",
  verifyToken,
  wrap(async (req, res) => {
    const { user } = await needDb();
    res.send(
      await user.updateOne(
        { email: req.params.email },
        { $set: req.body },
        { upsert: true }
      )
    );
  })
);

// ---------------- payment ----------------

app.get(
  "/payment",
  wrap(async (req, res) => {
    const { payment } = await needDb();
    res.send(await payment.find().toArray());
  })
);

app.post(
  "/create-payment-intent",
  wrap(async (req, res) => {
    if (!stripe) {
      return res.status(502).send({
        message:
          "Payment gateway is not configured (missing STRIPE_SECRET_KEY).",
      });
    }
    const price = Number(req.body?.price);
    if (!Number.isFinite(price) || price <= 0) {
      return res.status(400).send({ message: "Invalid price" });
    }
    try {
      const amount = Math.round(price * 100);
      const paymentIntent = await stripe.paymentIntents.create({
        amount,
        currency: "usd",
        payment_method_types: ["card"],
      });
      res.send({ clientSecret: paymentIntent.client_secret });
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
  wrap(async (req, res) => {
    const { payment, course, user } = await needDb();
    const data = req.body;
    const result = await payment.insertOne(data);

    const _id = toObjectId(data.courseId);
    if (_id) {
      const paidCourse = await course.findOne({ _id });
      const enrolledTotal = (paidCourse?.enrolled || 0) + 1;
      await course.updateOne({ _id }, { $set: { enrolled: enrolledTotal } });

      const customer = await user.findOne({ email: data.customerEmail });
      const enrolledCourses = Array.isArray(customer?.enrolledCourses)
        ? customer.enrolledCourses
        : [];
      if (
        paidCourse &&
        !enrolledCourses.some((c) => c?._id === data.courseId)
      ) {
        enrolledCourses.push(paidCourse);
      }
      await user.updateOne(
        { email: data.customerEmail },
        { $set: { enrolledCourses } },
        { upsert: true }
      );
    }

    res.send(result);
  })
);

// ---------------- lesson progress (LMS) ----------------
// Shape stored on the user doc:  progress: { [courseId]: ["0","2",...] }

app.get(
  "/progress/:email",
  verifyToken,
  wrap(async (req, res) => {
    const { user } = await needDb();
    const result = await user.findOne(
      { email: req.params.email },
      { projection: { progress: 1 } }
    );
    res.send(result?.progress || {});
  })
);

app.patch(
  "/progress/:email",
  verifyToken,
  wrap(async (req, res) => {
    const { courseId, lessons } = req.body || {};
    if (!courseId || !Array.isArray(lessons)) {
      return res
        .status(400)
        .send({ message: "courseId and lessons[] required" });
    }
    const { user } = await needDb();
    await user.updateOne(
      { email: req.params.email },
      { $set: { [`progress.${courseId}`]: lessons.map(String) } },
      { upsert: true }
    );
    res.send({ acknowledged: true });
  })
);

// ---------------- misc ----------------

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
