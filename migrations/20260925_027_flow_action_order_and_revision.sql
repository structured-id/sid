-- Actions are listed per hook point in their execution order, which needs a
-- column to sort on (the listing sorted on a column that did not exist). An
-- update applies over the revision it was read at, so a stale copy never
-- re-enables a disabled action or recreates a deleted one.
ALTER TABLE flow_actions ADD COLUMN IF NOT EXISTS action_order INTEGER NOT NULL DEFAULT 0;
ALTER TABLE flow_actions ADD COLUMN IF NOT EXISTS revision BIGINT NOT NULL DEFAULT 0
    CHECK (revision >= 0);

-- The hook point and order stored in `data` are the ones an update last
-- wrote; the columns were never updated with them.
UPDATE flow_actions
SET action_order = COALESCE((data->>'order')::integer, 0),
    action_point = COALESCE(data->>'action_point', action_point);
