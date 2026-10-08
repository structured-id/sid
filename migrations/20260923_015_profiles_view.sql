-- Read-only profile view for applications sharing the database (schema
-- isolation), over the current tables: email lives in profile_emails.
--
-- display_name follows the OIDC `name` claim algorithm: given, middle and
-- family name joined by spaces, empty parts skipped. email is the primary
-- address (standard PII mode, the only mode stored in clear).

CREATE OR REPLACE VIEW profiles_view AS
SELECT
    p.id,
    NULLIF(concat_ws(' ', p.given_name, p.middle_name, p.family_name), '') AS display_name,
    e.email,
    p.status AS profile_status,
    p.created_at,
    p.updated_at
FROM profiles p
LEFT JOIN profile_emails e ON e.profile_id = p.id AND e.is_primary;

CREATE OR REPLACE RULE profiles_view_no_insert AS
    ON INSERT TO profiles_view DO INSTEAD NOTHING;
CREATE OR REPLACE RULE profiles_view_no_update AS
    ON UPDATE TO profiles_view DO INSTEAD NOTHING;
CREATE OR REPLACE RULE profiles_view_no_delete AS
    ON DELETE TO profiles_view DO INSTEAD NOTHING;
