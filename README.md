# Avenor Server

REST API for the Avenor LMS (courses, users, payments, lesson progress).

## Stack

Express · MongoDB (Atlas) · Stripe · JWT · deployed on Vercel serverless.

## Setup

```bash
npm install
cp .env.example .env.local   # then fill in your own values
npm run dev                  # http://localhost:5000
```

## Environment variables

| Name | Purpose |
|---|---|
| `URI` | MongoDB Atlas connection string |
| `JWT_SECRET` | Secret used to sign auth tokens |
| `STRIPE_SECRET_KEY` | Stripe test/live secret key (`sk_test_...`) |
| `CLIENT_URL` | Comma-separated allowed frontend origins |
| `PORT` | Local port (default 5000) |

## API

| Method | Route | Auth | Description |
|---|---|---|---|
| GET | `/course` | — | All courses |
| GET | `/course/:id` | — | Single course |
| POST | `/course/add` | JWT | Create course |
| PATCH | `/course/edit/:id` | JWT | Update course |
| DELETE | `/course/delete/:id` | JWT | Delete course |
| GET | `/course/find/:email` | — | Courses by instructor email |
| POST | `/user` | — | Login/register sync → `{ token }` |
| GET | `/user/:email` | — | User profile (+ enrolledCourses) |
| PATCH | `/user/:email` | JWT | Update profile |
| GET | `/payment` | — | All payments |
| POST | `/create-payment-intent` | — | Stripe client secret |
| POST | `/payment` | — | Save payment + enroll customer |
| GET | `/progress/:email` | JWT | Lesson progress map `{ [courseId]: [lessonIdx] }` |
| PATCH | `/progress/:email` | JWT | Save completed lessons for a course |

## Notes

- Routes are registered at module load so they exist during serverless cold
  starts; handlers await the shared MongoDB connection.
- Every async handler is wrapped — failures return JSON errors instead of
  crashing the process.
- Secrets are read from environment variables only; never commit `.env*`.
