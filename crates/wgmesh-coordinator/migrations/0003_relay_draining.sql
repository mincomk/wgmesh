-- A relay under maintenance stops taking new pairs and hands the ones it carries over to
-- another relay. That is a report from the relay, not a decision by an operator, so it is
-- its own column rather than a `state`: `state` says what the operator decided, `draining`
-- says what the relay told us on its last heartbeat.
ALTER TABLE relays ADD COLUMN draining INTEGER NOT NULL DEFAULT 0;
