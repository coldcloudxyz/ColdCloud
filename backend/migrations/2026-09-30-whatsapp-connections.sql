CREATE TABLE IF NOT EXISTS whatsapp_connections (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  waba_id TEXT,
  phone_number_id TEXT,
  business_id TEXT,
  display_phone_number TEXT,
  verified_name TEXT,
  access_token_encrypted TEXT,
  status TEXT NOT NULL DEFAULT 'connected',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_whatsapp_connections_workspace
ON whatsapp_connections(workspace_id);
