require("dotenv").config({ path: ".env.local" });
const express = require("express");
const path = require("path");
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
      if (
        !origin ||
        allowedOrigins.includes(origin) ||
        /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)
      ) {
        return cb(null, true);
      }
      cb(null, true); // keep permissive until every deploy domain is listed
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
    res.status(500).send({ message: err?.message || "Server error" });
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

/** Boot-safe Mongo client: missing/invalid URI must not kill the process. */
let client = null;
if (process.env.URI) {
  client = new MongoClient(process.env.URI, {
    serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
    },
  });
} else {
  console.error(
    "FATAL: Missing URI env var (MongoDB connection string) — API routes disabled."
  );
}

async function run() {
  if (!client) return;
  try {
    await client.connect();
    const database = client.db("devdeive_course");
    const course = database.collection("course");
    const user = database.collection("user");
    const payment = database.collection("payment");

    //   course

    app.get(
      "/course",
      wrap(async (req, res) => {
        const result = await course.find().toArray();
        res.send(result);
      })
    );

    app.get(
      "/course/:id",
      wrap(async (req, res) => {
        const _id = toObjectId(req.params.id);
        if (!_id) return res.status(404).send(null);
        const result = await course.findOne({ _id });
        res.send(result);
      })
    );

    app.post(
      "/course/add",
      verifyToken,
      wrap(async (req, res) => {
        const result = await course.insertOne(req.body);
        res.send(result);
      })
    );

    app.delete(
      "/course/delete/:id",
      verifyToken,
      wrap(async (req, res) => {
        const _id = toObjectId(req.params.id);
        if (!_id) return res.status(404).send({ deletedCount: 0 });
        const result = await course.deleteOne({ _id });
        res.send(result);
      })
    );

    app.patch(
      "/course/edit/:id",
      verifyToken,
      wrap(async (req, res) => {
        const _id = toObjectId(req.params.id);
        if (!_id) return res.status(404).send({ matchedCount: 0 });
        const result = await course.updateOne({ _id }, { $set: req.body });
        res.send(result);
      })
    );

    app.get(
      "/course/find/:email",
      wrap(async (req, res) => {
        const result = await course
          .find({ authorEmail: req.params.email })
          .toArray();
        res.send(result);
      })
    );

    // user

    app.get(
      "/user",
      wrap(async (req, res) => {
        const result = await user.find().toArray();
        res.send(result);
      })
    );

    app.post(
      "/user",
      wrap(async (req, res) => {
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
        const result = await user.findOne({ email: req.params.email });
        res.send(result);
      })
    );

    app.patch(
      "/user/:email",
      verifyToken,
      wrap(async (req, res) => {
        const result = await user.updateOne(
          { email: req.params.email },
          { $set: req.body },
          { upsert: true }
        );
        res.send(result);
      })
    );

    // payment

    app.get(
      "/payment",
      wrap(async (req, res) => {
        const result = await payment.find().toArray();
        res.send(result);
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
        const amount = Math.round(price * 100);
        try {
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
        const data = req.body;
        const result = await payment.insertOne(data);

        const _id = toObjectId(data.courseId);
        if (_id) {
          const paidCourse = await course.findOne({ _id });
          const enrolledTotal = (paidCourse?.enrolled || 0) + 1;
          await course.updateOne(
            { _id },
            { $set: { enrolled: enrolledTotal } }
          );

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

    // ---- lesson progress (LMS) ----
    // Shape stored on the user doc:  progress: { [courseId]: ["0","2",...] }

    app.get(
      "/progress/:email",
      verifyToken,
      wrap(async (req, res) => {
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
          return res.status(400).send({ message: "courseId and lessons[] required" });
        }
        await user.updateOne(
          { email: req.params.email },
          { $set: { [`progress.${courseId}`]: lessons.map(String) } },
          { upsert: true }
        );
        res.send({ acknowledged: true });
      })
    );

    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
  }
}
run().catch(console.dir);

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "home.html"));
});

// Vercel serverless: export the app. Local/Render: keep the HTTP listener.
if (process.env.VERCEL) {
  module.exports = app;
} else {
  app.listen(port, () => {
    console.log(`Devdrive server listening on port ${port}`);
  });
}

