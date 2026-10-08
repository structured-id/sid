-- Seed OAuth2 clients for all internal structured.world sites.
--
-- Each client: subject_type=pairwise, org_id from structured.id org,
-- application_type=spa, token_endpoint_auth_method=none (public SPA clients).
--
-- Idempotent: ON CONFLICT (client_id) DO NOTHING.
-- Run against the CE database (sid).
--
-- Usage:
--   psql -h localhost -p 54320 -U sid -d sid \
--     -v org_id="'<structured.id-org-uuid>'" \
--     -f deploy/seed/seed_internal_clients.sql

-- personal-ui — User self-service dashboard (my.structured.id)
INSERT INTO oauth2_clients (
    client_id, project_id, application_type, client_name, active,
    redirect_uris, allowed_scopes, grant_types, response_types,
    token_endpoint_auth_method, subject_type, sector_identifier_uri,
    enforcement_mode, login_strategy, org_id, created_at
) VALUES (
    'sid-personal-ui',
    '00000000-0000-0000-0000-000000000000',
    'spa',
    'StructuredID Personal',
    TRUE,
    ARRAY['https://my.structured.id/callback'],
    'openid profile email',
    'authorization_code refresh_token',
    'code',
    'none',
    'pairwise',
    'https://my.structured.id/',
    'hard',
    'local_first',
    :org_id,
    NOW()
) ON CONFLICT (client_id) DO NOTHING;

-- admin-ui — CE IdP administration panel (admin.structured.id)
INSERT INTO oauth2_clients (
    client_id, project_id, application_type, client_name, active,
    redirect_uris, allowed_scopes, grant_types, response_types,
    token_endpoint_auth_method, subject_type, sector_identifier_uri,
    enforcement_mode, login_strategy, org_id, created_at
) VALUES (
    'sid-admin-ui',
    '00000000-0000-0000-0000-000000000000',
    'spa',
    'StructuredID Admin',
    TRUE,
    ARRAY['https://admin.structured.id/callback'],
    'openid profile email',
    'authorization_code refresh_token',
    'code',
    'none',
    'pairwise',
    'https://admin.structured.id/',
    'hard',
    'local_first',
    :org_id,
    NOW()
) ON CONFLICT (client_id) DO NOTHING;

-- frontend: SaaS user dashboard (structured.id)
INSERT INTO oauth2_clients (
    client_id, project_id, application_type, client_name, active,
    redirect_uris, allowed_scopes, grant_types, response_types,
    token_endpoint_auth_method, subject_type, sector_identifier_uri,
    enforcement_mode, login_strategy, org_id, created_at
) VALUES (
    'sid-frontend',
    '00000000-0000-0000-0000-000000000000',
    'spa',
    'StructuredID',
    TRUE,
    ARRAY['https://structured.id/callback'],
    'openid profile email',
    'authorization_code refresh_token',
    'code',
    'none',
    'pairwise',
    'https://structured.id/',
    'hard',
    'local_first',
    :org_id,
    NOW()
) ON CONFLICT (client_id) DO NOTHING;

-- structured-chat — Messaging app (chat.structured.id)
INSERT INTO oauth2_clients (
    client_id, project_id, application_type, client_name, active,
    redirect_uris, allowed_scopes, grant_types, response_types,
    token_endpoint_auth_method, subject_type, sector_identifier_uri,
    enforcement_mode, login_strategy, org_id, created_at
) VALUES (
    'sid-chat',
    '00000000-0000-0000-0000-000000000000',
    'spa',
    'Structured Chat',
    TRUE,
    ARRAY['https://chat.structured.id/callback'],
    'openid profile email',
    'authorization_code refresh_token',
    'code',
    'none',
    'pairwise',
    'https://chat.structured.id/',
    'hard',
    'local_first',
    :org_id,
    NOW()
) ON CONFLICT (client_id) DO NOTHING;

-- structured-wallet — Crypto wallet app (wallet.structured.id)
INSERT INTO oauth2_clients (
    client_id, project_id, application_type, client_name, active,
    redirect_uris, allowed_scopes, grant_types, response_types,
    token_endpoint_auth_method, subject_type, sector_identifier_uri,
    enforcement_mode, login_strategy, org_id, created_at
) VALUES (
    'sid-wallet',
    '00000000-0000-0000-0000-000000000000',
    'spa',
    'Structured Wallet',
    TRUE,
    ARRAY['https://wallet.structured.id/callback'],
    'openid profile email',
    'authorization_code refresh_token',
    'code',
    'none',
    'pairwise',
    'https://wallet.structured.id/',
    'hard',
    'local_first',
    :org_id,
    NOW()
) ON CONFLICT (client_id) DO NOTHING;

-- pwrqr — QR code generator (pwrqr.com)
INSERT INTO oauth2_clients (
    client_id, project_id, application_type, client_name, active,
    redirect_uris, allowed_scopes, grant_types, response_types,
    token_endpoint_auth_method, subject_type, sector_identifier_uri,
    enforcement_mode, login_strategy, org_id, created_at
) VALUES (
    'sid-pwrqr',
    '00000000-0000-0000-0000-000000000000',
    'spa',
    'PwrQR',
    TRUE,
    ARRAY['https://pwrqr.com/callback'],
    'openid profile email',
    'authorization_code refresh_token',
    'code',
    'none',
    'pairwise',
    'https://pwrqr.com/',
    'hard',
    'local_first',
    :org_id,
    NOW()
) ON CONFLICT (client_id) DO NOTHING;
