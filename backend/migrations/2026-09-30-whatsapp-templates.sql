CREATE TABLE IF NOT EXISTS whatsapp_templates (
  id TEXT PRIMARY KEY,
  workspace_id TEXT NOT NULL,
  name TEXT NOT NULL,
  category TEXT NOT NULL DEFAULT 'MARKETING',
  language TEXT NOT NULL DEFAULT 'en_US',
  body_text TEXT NOT NULL,
  use_type TEXT,
  use_label TEXT,
  provider_template_id TEXT,
  provider_template_name TEXT,
  provider_status TEXT NOT NULL DEFAULT 'not_submitted',
  rejection_reason TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_whatsapp_templates_workspace_name
ON whatsapp_templates(workspace_id, provider_template_name);

CREATE INDEX IF NOT EXISTS idx_whatsapp_templates_workspace_status
ON whatsapp_templates(workspace_id, provider_status);