// ─────────────────────────────────────────────────────────────
// Database migration — run once to create all tables
// Usage: node migrate.js
// ─────────────────────────────────────────────────────────────
require('dotenv').config()
const { query } = require('./db')

async function migrate() {
  console.log('[Migrate] Creating tables...')

  await query(`
    CREATE TABLE IF NOT EXISTS users (
      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email           TEXT UNIQUE NOT NULL,
      password        TEXT NOT NULL,
      name            TEXT NOT NULL,
      company         TEXT,
      biz_desc        TEXT,
      sender_name     TEXT,
      sender_phone    TEXT,
      sender_email    TEXT,
      sign_off        TEXT,
      twilio_sid      TEXT,
      twilio_token    TEXT,
      twilio_phone    TEXT,
      twilio_wa       TEXT,
      twilio_mode     TEXT DEFAULT 'shared',
      custom_messages TEXT DEFAULT '{}',
      sequence_config JSONB DEFAULT '{
        "step1": {"enabled": true, "delayDays": 0, "channel": "whatsapp"},
        "step2": {"enabled": true, "delayDays": 3, "channel": "sms"},
        "step3": {"enabled": true, "delayDays": 5, "channel": "call"},
        "step4": {"enabled": true, "delayDays": 7, "channel": "whatsapp"}
      }',
      created_at      TIMESTAMPTZ DEFAULT NOW(),
      updated_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `)
  console.log('[Migrate] ✓ users')

  await query(`
    CREATE TABLE IF NOT EXISTS leads (
      id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id          UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name             TEXT NOT NULL,
      phone            TEXT NOT NULL,
      context          TEXT NOT NULL,
      notes            TEXT DEFAULT '',
      business         TEXT DEFAULT '',
      channels         TEXT[] DEFAULT ARRAY['whatsapp','sms','call'],
      status           TEXT DEFAULT 'active'
                         CHECK (status IN ('active','replied','converted','completed','unsubscribed')),
      current_step     INT DEFAULT 0,
      next_follow_up_at TIMESTAMPTZ,
      total_sent       INT DEFAULT 0,
      replied_at       TIMESTAMPTZ,
      converted_at     TIMESTAMPTZ,
      opted_out_at     TIMESTAMPTZ,
      created_at       TIMESTAMPTZ DEFAULT NOW(),
      updated_at       TIMESTAMPTZ DEFAULT NOW()
    )
  `)
  await query(`CREATE INDEX IF NOT EXISTS leads_user_id_idx   ON leads(user_id)`)
  await query(`CREATE INDEX IF NOT EXISTS leads_status_idx    ON leads(status)`)
  await query(`CREATE INDEX IF NOT EXISTS leads_followup_idx  ON leads(next_follow_up_at) WHERE status = 'active'`)
  console.log('[Migrate] ✓ leads')

  await query(`
    CREATE TABLE IF NOT EXISTS messages (
      id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      lead_id         UUID NOT NULL REFERENCES leads(id) ON DELETE CASCADE,
      lead_name       TEXT NOT NULL,
      type            TEXT NOT NULL CHECK (type IN ('whatsapp','sms','call','reply')),
      direction       TEXT NOT NULL CHECK (direction IN ('outbound','inbound')),
      body            TEXT NOT NULL,
      status          TEXT DEFAULT 'queued'
                        CHECK (status IN ('queued','sent','delivered','failed','received')),
      delivery_status TEXT DEFAULT 'queued',
      twilio_sid      TEXT,
      step            INT DEFAULT 0,
      error_message   TEXT,
      created_at      TIMESTAMPTZ DEFAULT NOW()
    )
  `)
  await query(`CREATE INDEX IF NOT EXISTS messages_user_id_idx  ON messages(user_id)`)
  await query(`CREATE INDEX IF NOT EXISTS messages_lead_id_idx  ON messages(lead_id)`)
  await query(`CREATE INDEX IF NOT EXISTS messages_created_idx  ON messages(created_at DESC)`)
  console.log('[Migrate] ✓ messages')

  // Auto-update updated_at
  await query(`
    CREATE OR REPLACE FUNCTION update_updated_at()
    RETURNS TRIGGER AS $$
    BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
    $$ LANGUAGE plpgsql
  `)
  await query(`
    DROP TRIGGER IF EXISTS users_updated_at ON users;
    CREATE TRIGGER users_updated_at BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at()
  `)
  await query(`
    DROP TRIGGER IF EXISTS leads_updated_at ON leads;
    CREATE TRIGGER leads_updated_at BEFORE UPDATE ON leads
    FOR EACH ROW EXECUTE FUNCTION update_updated_at()
  `)

  console.log('[Migrate] ✅ All tables ready')
  process.exit(0)
}

migrate().catch(err => {
  console.error('[Migrate] Failed:', err.message)
  process.exit(1)
})
