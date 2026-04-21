# 🎓 ElimuPay — Educational Video Platform

A pay-per-session educational video platform for Kenyan students.  
Pay **KES 10 via M-Pesa** and get **30 minutes of video access**.

---

## 🚀 Quick Start

### 1. Clone & Install
```bash
git clone <your-repo-url>
cd elimu-pay
npm install
```

### 2. Configure Environment
```bash
cp .env.example .env
# Fill in your actual values in .env
```

### 3. Set Up Database
- Go to [supabase.com](https://supabase.com) → SQL Editor
- Paste and run `setup.sql`

### 4. Run the Server
```bash
npm run dev      # development (auto-restart)
npm start        # production
```

---

## 📡 API Endpoints

### Auth
| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/register` | Create a new account |
| POST | `/api/login` | Login and get JWT |
| GET  | `/api/check-access` | Check if user has active session |

### Payments
| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/pay/initiate` | Trigger M-Pesa STK push |
| POST | `/api/pay/callback` | M-Pesa webhook (auto-called) |
| GET  | `/api/pay/status/:id` | Check payment status |

### Videos (paid access required)
| Method | Route | Description |
|--------|-------|-------------|
| GET  | `/api/videos` | List all active videos |
| POST | `/api/videos/:id/view` | Record a video view |

### Admin
| Method | Route | Description |
|--------|-------|-------------|
| POST | `/api/admin/login` | Admin login |
| GET  | `/api/admin/stats` | Dashboard stats |
| GET  | `/api/admin/users` | All users |
| GET  | `/api/admin/payments` | All payments |
| GET  | `/api/admin/attempts` | Login attempts |
| POST | `/api/admin/videos` | Add a video |
| DELETE | `/api/admin/videos/:id` | Remove a video |

---

## 🛠️ Tech Stack

- **Backend:** Node.js + Express
- **Database:** Supabase (PostgreSQL)
- **Auth:** JWT + bcrypt
- **Payments:** M-Pesa Daraja API (STK Push)
- **Security:** Helmet, Rate Limiting
- **Hosting:** Render

---

## 🔐 Security Features

- JWT authentication (7-day expiry)
- bcrypt password hashing (12 rounds)
- Rate limiting on login/register (20 req/15min)
- Helmet security headers
- Phone number validation before STK push
- Admin role separation

---

## ⚙️ Environment Variables

See `.env.example` for all required variables.

---

## 📞 Support

Built for Kenyan students 🇰🇪 | M-Pesa sandbox by default.  
Switch `MPESA_ENV=live` in `.env` for production payments.
