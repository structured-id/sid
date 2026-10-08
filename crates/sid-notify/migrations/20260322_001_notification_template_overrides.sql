-- Custom notification template overrides.
-- Stores admin-modified template content per channel + locale.
-- Defaults remain in-memory; DB stores only customizations.
-- Reset = DELETE row (reverts to in-memory default).

CREATE TABLE IF NOT EXISTS notification_template_overrides (
    template_id TEXT NOT NULL,
    channel     SMALLINT NOT NULL,  -- 1=email, 2=sms, 3=push
    locale      TEXT NOT NULL DEFAULT 'en',

    -- Email fields
    subject     TEXT NOT NULL DEFAULT '',
    html_body   TEXT NOT NULL DEFAULT '',
    text_body   TEXT NOT NULL DEFAULT '',

    -- SMS fields
    sms_body    TEXT NOT NULL DEFAULT '',

    -- Push fields
    push_title  TEXT NOT NULL DEFAULT '',
    push_body   TEXT NOT NULL DEFAULT '',
    push_action_url TEXT NOT NULL DEFAULT '',

    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (template_id, channel, locale)
);

CREATE INDEX IF NOT EXISTS idx_template_overrides_template_id
    ON notification_template_overrides (template_id);
