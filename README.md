# Avenor Server

REST API for the Avenor learning management system: courses, enrollments, payments, quizzes, certificates, reviews and analytics. Built with Express and MongoDB (Atlas), deployed on Vercel serverless functions.

## Stack

Express · MongoDB Atlas · Stripe · JWT · express-rate-limit · sanitize-html

## Getting started

```bash
npm install
cp .env.example .env.local   # fill in your own values
node index.js                # http://localhost:5000
```

On boot the server connects to MongoDB, creates hot-path indexes, and registers all routes. If the database is unreachable the API still starts — data routes return a 503 JSON error until the connection recovers.

## Environment variables

| Name | Required | Purpose |
|---|---|---|
| `URI` | yes | MongoDB Atlas connection string |
| `JWT_SECRET` | yes | Secret used to sign auth tokens |
| `STRIPE_SECRET_KEY` | for payments | Stripe secret key (`sk_test_...` / `sk_live_...`) |
| `CLIENT_URL` | recommended | Comma-separated frontend origins; first public entry is used in `sitemap.xml` |
| `ADMIN_EMAILS` | optional | Comma-separated emails promoted to `role: admin` at login |
| `INSTRUCTOR_SHARE` | optional | Instructor cut of each sale, default `0.7` (70/30) |
| `DB_NAME` | optional | Override database name (used by the test suites) |
| `PORT` | optional | Local port, default `5000` |

## API overview

### Public

| Method | Route | Description |
|---|---|---|
| GET | `/course` | All courses |
| GET | `/course/:id` | Single course |
| GET | `/courses/search` | Catalog search: `?q&category&level&maxprice&sort&page&limit` |
| GET | `/courses/categories` | Distinct category list |
| GET | `/course/reviews/:id` | Reviews for a course (caller's own review flagged) |
| GET | `/quiz/:courseId` | Quiz questions without the answer key |
| GET | `/questions/:courseId` | Course Q&A thread |
| GET | `/coupons/validate/:code` | Coupon check for checkout |
| GET | `/certificates/verify/:code` | Public certificate verification |
| GET | `/sitemap.xml` | Sitemap with static pages and all course URLs |

### Authenticated (Bearer JWT)

| Method | Route | Description |
|---|---|---|
| POST | `/user` | Login/register sync, returns `{ token }`. Rate limited |
| GET | `/users/me` | Own profile incl. enrolled courses |
| PATCH | `/user/:email` | Update own profile (self or admin) |
| GET/PATCH | `/progress/:email` | Completed lessons per course |
| GET | `/progress/state/:email` | Progress + resume positions + last lesson |
| PATCH | `/notes/:courseId` | Timestamped lesson notes |
| GET/POST | `/wishlist`, `/wishlist/:courseId` | Wishlist list and toggle |
| GET/POST/DELETE | `/course/reviews/:id` | Reviews — enrolled users only, one per user |
| PUT | `/quiz/:courseId` | Create/update course quiz (author or admin) |
| POST | `/quiz/:courseId/attempt` | Submit answers, graded server-side |
| GET | `/quiz/:courseId/attempts/me` | Latest attempt |
| POST | `/certificates/:courseId` | Claim certificate (all lessons done + quiz passed) |
| GET | `/certificates/mine` | Own certificates |
| POST | `/questions/:courseId`, `/questions/:id/reply` | Ask and reply (enrolled users) |
| DELETE | `/questions/:id` | Delete own question |
| POST | `/create-payment-intent` | Stripe client secret, priced from the course document. Rate limited |
| POST | `/payment` | Record sale. Verifies intent status and amount against Stripe before enrolling |
| GET | `/payments/me` | Own purchases and sales |
| GET | `/analytics/instructor` | Earnings, per-course rollups, reviews, students |
| POST | `/course/add`, PATCH `/course/edit/:id`, DELETE `/course/delete/:id` | Course authoring — ownership enforced |
| GET | `/course/find/:email` | Courses by author email (self or admin) |
| GET | `/course/access/:id` | Watch access check (paid, free, author or admin) |

### Admin only

| Method | Route | Description |
|---|---|---|
| GET | `/admin/stats` | Marketplace totals and revenue split |
| GET/PATCH | `/admin/users`, `/admin/users/:email` | User roster, role changes, suspensions |
| PATCH | `/admin/courses/:id/featured` | Feature/unfeature a course |
| GET/POST/DELETE | `/admin/coupons`, `/admin/coupons/:code` | Coupon management |
| GET | `/payment`, `/user` | Full ledgers and user roster |
| GET | `/course` (all fields) | Unrestricted catalog access |

Roles travel inside the JWT (`student` / `instructor` / `admin`) and are re-checked server-side on every protected route.

## Payments flow

1. Client requests an intent with `courseId` (+ optional coupon). The amount is computed from the course document — client-supplied prices are ignored.
2. Card is confirmed with Stripe Elements.
3. The client posts the payment intent id; the server retrieves it from Stripe, requires `status === "succeeded"` and a matching amount, then records the sale with `instructorShare` / `platformFee` and grants enrollment.

## Tests

Integration tests run against a throwaway database:

```bash
ADMIN_EMAILS=a@phase4.test DB_NAME=test_run node index.js &
DB_NAME=test_run node tests/security.test.mjs
```

Suites: `security.test.mjs` (roles, ownership, scoping), `catalog-learning.test.mjs` (search, reviews, wishlist, progress), `quizzes-certificates.test.mjs`, `admin-commerce.test.mjs`.

## Deployment notes

- Routes are registered at module load so they exist during cold starts.
- The MongoDB connection retries per request instead of caching a failed connect, so a transient Atlas blip cannot poison a serverless instance.
- Secrets are read from environment variables only.
