-- Back-channel logouts are durable work: an undeliverable one is a failed
-- `logout.backchannel` record. Earlier dead-letter rows become such records
-- (payload as the delivery the worker reads), and their table goes.
INSERT INTO durable_work (
    id, kind, payload, state, attempts, max_attempts, generation,
    last_error, not_before, created_at, updated_at
)
SELECT
    id,
    'logout.backchannel',
    convert_to(
        json_build_object(
            'client_id', client_id,
            'profile_id', profile_id,
            'session_id', COALESCE(session_id, '')
        )::text,
        'UTF8'
    ),
    'failed',
    attempts,
    GREATEST(attempts, 1),
    0,
    last_error,
    last_attempted_at,
    created_at,
    last_attempted_at
FROM logout_dlq
ON CONFLICT (id) DO NOTHING;

DROP TABLE IF EXISTS logout_dlq;
