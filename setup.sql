-- ════════════════════════════════════════════════════════
-- ElimuPay Database Setup
-- Run this in your Supabase SQL Editor (supabase.com)
-- ════════════════════════════════════════════════════════

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  username    TEXT UNIQUE NOT NULL,
  password    TEXT NOT NULL,         -- bcrypt hashed
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- 2. LOGIN ATTEMPTS TABLE (for your admin dashboard)
CREATE TABLE IF NOT EXISTS login_attempts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  username    TEXT,
  ip          TEXT,
  user_agent  TEXT,
  status      TEXT CHECK (status IN ('success', 'failed')),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- 3. PAYMENTS TABLE
CREATE TABLE IF NOT EXISTS payments (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID REFERENCES users(id),
  username             TEXT,
  phone                TEXT,
  amount               INTEGER DEFAULT 10,
  checkout_request_id  TEXT UNIQUE,
  mpesa_ref            TEXT,
  status               TEXT CHECK (status IN ('pending', 'paid', 'failed')) DEFAULT 'pending',
  created_at           TIMESTAMPTZ DEFAULT NOW()
);

-- 4. SESSIONS TABLE (tracks 30-min access windows)
CREATE TABLE IF NOT EXISTS sessions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id),
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── INDEXES ──────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_attempts_created ON login_attempts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_payments_checkout ON payments(checkout_request_id);

-- ── ROW LEVEL SECURITY ───────────────────────────────────
-- Disable RLS since we use service key from backend
ALTER TABLE users         DISABLE ROW LEVEL SECURITY;
ALTER TABLE login_attempts DISABLE ROW LEVEL SECURITY;
ALTER TABLE payments       DISABLE ROW LEVEL SECURITY;
ALTER TABLE sessions       DISABLE ROW LEVEL SECURITY;
