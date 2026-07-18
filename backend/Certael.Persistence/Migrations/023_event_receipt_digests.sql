ALTER TABLE certael_event_receipts
  ADD COLUMN IF NOT EXISTS envelope_digest bytea NULL;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'certael_event_receipts_envelope_digest_check'
  ) THEN
    ALTER TABLE certael_event_receipts ADD CONSTRAINT certael_event_receipts_envelope_digest_check
      CHECK (envelope_digest IS NULL OR octet_length(envelope_digest)=32);
  END IF;
END
$$;
