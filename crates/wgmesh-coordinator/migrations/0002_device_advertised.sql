-- The design's data model has nowhere to keep the bands a device routes for
-- others, and the config snapshot has to report them per peer. One column,
-- defaulting to an empty list, extends the model without touching a table the
-- design fixed.
ALTER TABLE devices ADD COLUMN advertised TEXT NOT NULL DEFAULT '[]';
