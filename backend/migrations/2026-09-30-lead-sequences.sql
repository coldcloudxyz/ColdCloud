ALTER TABLE leads ADD COLUMN sequence_id TEXT;
ALTER TABLE leads ADD COLUMN sequence_progress INTEGER DEFAULT 0;
ALTER TABLE leads ADD COLUMN sequence_plan TEXT DEFAULT '[]';
