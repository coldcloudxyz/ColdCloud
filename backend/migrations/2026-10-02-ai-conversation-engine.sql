CREATE TABLE IF NOT EXISTS ai_events (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  lead_id TEXT,
  provider_message_id TEXT,
  event_type TEXT NOT NULL DEFAULT 'conversation',
  action TEXT,
  intent TEXT,
  confidence REAL,
  summary TEXT,
  reply_text TEXT,
  status TEXT NOT NULL DEFAULT 'ok',
  error_text TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ai_events_workspace_created
ON ai_events(workspace_id, created_at);

CREATE INDEX IF NOT EXISTS idx_ai_events_lead_created
ON ai_events(lead_id, created_at);

CREATE TABLE IF NOT EXISTS ai_message_locks (
  provider_message_id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  lead_id TEXT,
  status TEXT NOT NULL DEFAULT 'processing',
  error_text TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_ai_message_locks_workspace
ON ai_message_locks(workspace_id, created_at);
