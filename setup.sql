-- ════════════════════════════════════════════════════════
-- ElimuPay Database Setup v2
-- Run this in your Supabase SQL Editor (supabase.com)
-- ════════════════════════════════════════════════════════

-- 1. USERS TABLE
CREATE TABLE IF NOT EXISTS users (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name        TEXT NOT NULL,
  email       TEXT UNIQUE NOT NULL,
  password    TEXT NOT NULL,             -- bcrypt hashed (12 rounds)
  is_banned   BOOLEAN DEFAULT FALSE,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- 2. LOGIN ATTEMPTS TABLE
CREATE TABLE IF NOT EXISTS login_attempts (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email       TEXT,
  ip          TEXT,
  user_agent  TEXT,
  status      TEXT CHECK (status IN ('success', 'failed')),
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- 3. PAYMENTS TABLE
CREATE TABLE IF NOT EXISTS payments (
  id                   UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id              UUID REFERENCES users(id) ON DELETE SET NULL,
  email                TEXT,
  phone                TEXT,
  amount               INTEGER DEFAULT 10,
  checkout_request_id  TEXT UNIQUE,
  mpesa_ref            TEXT,
  status               TEXT CHECK (status IN ('pending', 'paid', 'failed')) DEFAULT 'pending',
  created_at           TIMESTAMPTZ DEFAULT NOW()
);

-- 4. SESSIONS TABLE (30-min access windows)
CREATE TABLE IF NOT EXISTS sessions (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- 5. VIDEOS TABLE
CREATE TABLE IF NOT EXISTS videos (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title       TEXT NOT NULL,
  description TEXT,
  url         TEXT NOT NULL,
  thumbnail   TEXT,
  subject     TEXT,
  grade       TEXT,
  duration    INTEGER,               -- seconds
  is_active   BOOLEAN DEFAULT TRUE,
  views       INTEGER DEFAULT 0,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- 6. PASSWORD RESETS TABLE
CREATE TABLE IF NOT EXISTS password_resets (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id     UUID REFERENCES users(id) ON DELETE CASCADE,
  email       TEXT NOT NULL,
  token       TEXT UNIQUE NOT NULL,
  used        BOOLEAN DEFAULT FALSE,
  expires_at  TIMESTAMPTZ NOT NULL,
  created_at  TIMESTAMPTZ DEFAULT NOW()
);

-- ── INDEXES ─────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_users_email         ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_banned        ON users(is_banned);
CREATE INDEX IF NOT EXISTS idx_attempts_created    ON login_attempts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_sessions_user       ON sessions(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_expires    ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_payments_checkout   ON payments(checkout_request_id);
CREATE INDEX IF NOT EXISTS idx_payments_status     ON payments(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_videos_subject      ON videos(subject, grade);
CREATE INDEX IF NOT EXISTS idx_videos_active       ON videos(is_active, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_videos_views        ON videos(views DESC);
CREATE INDEX IF NOT EXISTS idx_resets_token        ON password_resets(token);
CREATE INDEX IF NOT EXISTS idx_resets_expires      ON password_resets(expires_at);

-- ── ADMIN STATS VIEW ─────────────────────────────────────
CREATE OR REPLACE VIEW admin_stats AS
SELECT
  (SELECT COUNT(*)                          FROM users)                                  AS total_users,
  (SELECT COUNT(*)                          FROM payments WHERE status = 'paid')          AS total_paid,
  (SELECT COALESCE(SUM(amount), 0)          FROM payments WHERE status = 'paid')          AS total_revenue,
  (SELECT COUNT(*)                          FROM payments WHERE status = 'pending')       AS pending_payments,
  (SELECT COUNT(*)                          FROM videos   WHERE is_active = TRUE)         AS active_videos,
  (SELECT COUNT(*)                          FROM sessions WHERE expires_at > NOW())       AS active_sessions;

-- ── CLEANUP FUNCTION (run periodically via cron or pg_cron) ──
CREATE OR REPLACE FUNCTION cleanup_expired()
RETURNS void AS $$
BEGIN
  DELETE FROM sessions       WHERE expires_at < NOW() - INTERVAL '7 days';
  DELETE FROM password_resets WHERE expires_at < NOW() OR used = TRUE;
END;
$$ LANGUAGE plpgsql;

-- ── ROW LEVEL SECURITY ───────────────────────────────────
-- Disabled — we use service key from backend
ALTER TABLE users           DISABLE ROW LEVEL SECURITY;
ALTER TABLE login_attempts  DISABLE ROW LEVEL SECURITY;
ALTER TABLE payments        DISABLE ROW LEVEL SECURITY;
ALTER TABLE sessions        DISABLE ROW LEVEL SECURITY;
ALTER TABLE videos          DISABLE ROW LEVEL SECURITY;
ALTER TABLE password_resets DISABLE ROW LEVEL SECURITY;
