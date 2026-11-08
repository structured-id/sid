// SPDX-License-Identifier: AGPL-3.0-only
//! Every table of the SQLite schema moves with the snapshot, except the ones
//! named in [`NOT_MOVED`] with the reason they hold no state a move must
//! keep. A source populated in every moved table is exported and imported
//! into a blank installation, and each table holds the same rows after it.

use std::collections::BTreeMap;

use chrono::{Duration, SubsecRound, Utc};
use sid_authn::snapshot_rules::AuthnSnapshotRules;
use sid_core::models::consent::{ClaimType, ConsentRecord, ConsentStatus};
use sid_core::models::notification::NotificationPreferences;
use sid_core::models::*;
use sid_plugin::storage::StorageBackend;
use sid_plugin::{CredentialStore, GrantStore, IssuerStore, OperationResultStore};
use sid_storage::snapshot;
use sid_storage::sqlite::{SqliteAuditLog, SqliteBackend};
use uuid::Uuid;

/// Tables whose rows a move does not carry, with the reason.
const NOT_MOVED: &[(&str, &str)] = &[(
    "job_locks",
    "a held lock belongs to the process that took it; the moved \
     installation's workers take their own",
)];

/// Tables the import appends to after the rows it moved, with the reason;
/// every source row must still be there, as it was.
const CONTINUED: &[(&str, &str)] = &[
    (
        "audit_records",
        "the import records each write it makes on the chains it moved",
    ),
    (
        "history_key_audit",
        "the import records each write it makes to the evaluator's store after \
         the trail it moved",
    ),
];

/// Tables whose rows the import itself advances, compared by `verify`
/// instead, with the reason.
const ADVANCED: &[(&str, &str)] = &[(
    "audit_chain_heads",
    "a chain the import wrote to has its head past the source's; verify checks \
     that every target chain holds its source chain",
)];

/// Rows a store writes for itself, by the table and the start of the row:
/// each installation keeps its own.
const SEEDED: &[(&str, &str, &str)] = &[
    (
        "projects",
        "X'00000000000000000000000000000000'",
        "the system project, created with the schema of each store",
    ),
    (
        "operation_resources",
        "'snapshot-import'",
        "the record of the import itself, by which an interrupted one resumes",
    ),
];

/// Columns a store writes for itself, by table and column: no reader uses
/// them beyond the store that wrote them.
const OWN_COLUMNS: &[(&str, &str, &str)] = &[
    (
        "operation_resources",
        "bound_at_ms",
        "when this store bound the identifier; read only to order an export",
    ),
    (
        "key_versions",
        "created_at",
        "when this store recorded the derivation parameters; never read",
    ),
    (
        "history_key_versions",
        "created_at",
        "when this store recorded the derivation parameters; never read",
    ),
    (
        "instance_secrets",
        "created_at",
        "when this store recorded the sealed secret; never read",
    ),
    (
        "bootstrap_policy",
        "adopted_at",
        "when this store recorded central management; never read",
    ),
    (
        "enrollment_policy",
        "updated_at",
        "when this store recorded the policy; never read",
    ),
];

fn ctx() -> MutationContext {
    AuditEntry::system("test", "coverage").into()
}

/// A quoted column value with a time in it written at microsecond
/// precision: stores write the same instant at millisecond or microsecond
/// precision depending on the path that wrote it.
fn normalized(value: &str) -> String {
    let Some(text) = value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')) else {
        return value.to_owned();
    };
    match chrono::DateTime::parse_from_rfc3339(text) {
        Ok(time) => format!(
            "'{}'",
            time.with_timezone(&Utc)
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        ),
        Err(_) => value.to_owned(),
    }
}

/// Every row of every table of `backend`, each as the quoted values of all
/// its columns, sorted.
async fn rows(backend: &SqliteBackend) -> BTreeMap<String, Vec<String>> {
    let names: Vec<(String,)> = sqlx::query_as(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'",
    )
    .fetch_all(backend.pool())
    .await
    .unwrap();
    let mut tables = BTreeMap::new();
    for (name,) in names {
        let columns: Vec<(String,)> =
            sqlx::query_as("SELECT name FROM pragma_table_info(?) ORDER BY cid")
                .bind(&name)
                .fetch_all(backend.pool())
                .await
                .unwrap();
        let values = columns
            .iter()
            .map(|(c,)| format!("quote(\"{c}\")"))
            .collect::<Vec<_>>()
            .join(", ");
        // The names come from the schema catalogue, not from input.
        let sql = sqlx::AssertSqlSafe(format!("SELECT {values} FROM \"{name}\""));
        let mut rows: Vec<String> = sqlx::query(sql)
            .fetch_all(backend.pool())
            .await
            .unwrap()
            .iter()
            .map(|row| {
                columns
                    .iter()
                    .enumerate()
                    .map(|(i, (column,))| {
                        if OWN_COLUMNS
                            .iter()
                            .any(|(t, c, _)| *t == name && c == column)
                        {
                            "*".to_owned()
                        } else {
                            normalized(&sqlx::Row::get::<String, _>(row, i))
                        }
                    })
                    .collect::<Vec<_>>()
                    .join("|")
            })
            .filter(|row| {
                !SEEDED
                    .iter()
                    .any(|(table, start, _)| *table == name && row.starts_with(start))
            })
            .collect();
        rows.sort();
        tables.insert(name, rows);
    }
    tables
}

/// The installation: its organization, an issuer with its key, an
/// application holding a client and a resource, and the client's access.
struct Installation {
    client: OAuth2Client,
    resource: ProtectedResource,
}

async fn installation(source: &SqliteBackend) -> Installation {
    let org = Organization::implicit_community("sid.example.com");
    source
        .insert_instance_organization(&org, ctx())
        .await
        .unwrap();
    let now = Utc::now().trunc_subsecs(3);
    let handle = IssuerHandle::generate();
    let issuer = OidcIssuer {
        id: IssuerId::generate(),
        canonical_url: format!("https://sid.example.com/i/{handle}"),
        handle,
        authority: IssuerAuthority::Local,
        recipient_org: org.id,
        created_at: now,
    };
    let key = IssuerSigningKey {
        issuer_id: issuer.id,
        generation: 1,
        key_id: "kid".into(),
        public_key: [3; 32],
        sealed_private_key: vec![1],
        created_at: now,
    };
    source
        .insert_oidc_issuer(&issuer, &key, ctx())
        .await
        .unwrap();
    let app = Application {
        id: ApplicationId::generate(),
        project_id: ProjectId::SYSTEM,
        name: "Orders".into(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let resource = ProtectedResource {
        id: ResourceId::generate(),
        application_id: Some(app.id),
        issuer_id: issuer.id,
        indicator: ResourceIndicator::parse("https://resources.example/orders").unwrap(),
        scopes: vec!["orders.read".into()],
        state: ResourceState::Active,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let client = client_for(&app, org.id);
    source
        .create_application(&app, Some(&client), Some(&resource), ctx())
        .await
        .unwrap();
    source
        .set_resource_access(
            &ResourceAccess {
                client_id: client.client_id.clone(),
                resource_id: resource.id,
                scopes: vec!["orders.read".into()],
                created_at: now,
            },
            ctx(),
        )
        .await
        .unwrap();
    Installation { client, resource }
}

/// A client role of `app` in organization `org`.
fn client_for(app: &Application, org: OrgId) -> OAuth2Client {
    OAuth2Client {
        client_id: format!("client-{}", app.id),
        project_id: app.project_id,
        application_id: app.id,
        default_resource: None,
        application_type: ApplicationType::Web,
        client_secret_hash: None,
        jwks: None,
        redirect_uris: vec!["https://app.sid.example.com/cb".into()],
        allowed_scopes: vec!["openid".into()],
        grant_types: vec!["authorization_code".into()],
        client_name: app.name.clone(),
        logo_uri: None,
        active: true,
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        response_types: vec!["code".into()],
        subject_type: SubjectType::Public,
        sector_identifier_uri: None,
        contacts: vec![],
        client_id_issued_at: app.created_at,
        client_secret_expires_at: None,
        registration_iat: None,
        registration_access_token_hash: None,
        required_acr: None,
        required_amr: vec![],
        enforcement_mode: EnforcementMode::Audit,
        min_device_assurance: None,
        require_verified_email: None,
        require_verified_phone: None,
        backchannel_logout_uri: None,
        backchannel_logout_session_required: false,
        post_logout_redirect_uris: vec![],
        claim_mappings: vec![],
        login_strategy: LoginStrategy::LocalFirst,
        show_federation_button: true,
        federation_timeout_ms: 500,
        unified_input: false,
        org_id: Some(org),
        revision: 0,
        created_at: app.created_at,
    }
}

/// A signed-in profile: a session that authorized a code redeemed into
/// another one holding a rotated refresh token family and a rotated native
/// generation.
async fn signed_in(source: &SqliteBackend, installation: &Installation) -> Profile {
    let profile = Profile::new(Some("coverage"));
    source.create_profile(&profile, ctx()).await.unwrap();
    let expires = Utc::now() + Duration::hours(1);
    let authorizing = Session::new(profile.id, None, expires);
    source
        .create_session_atomic(&authorizing, 0, None, ctx())
        .await
        .unwrap();
    let code = AuthorizationCode {
        code_hash: Uuid::now_v7().as_bytes().to_vec(),
        profile_id: profile.id,
        client_id: installation.client.client_id.clone(),
        redirect_uri: "https://app.sid.example.com/cb".into(),
        scopes: vec!["openid".into()],
        resource: installation.resource.id,
        code_challenge: None,
        nonce: None,
        authentication: authorizing.grant_authentication(),
        expires_at: Utc::now() + Duration::minutes(5),
        created_at: Utc::now(),
        used: false,
        session_id: None,
    };
    source.create_auth_code(&code, ctx()).await.unwrap();
    let session = Session::new(profile.id, None, expires);
    let token = |family: Uuid| RefreshToken {
        id: Uuid::now_v7(),
        token_hash: Uuid::now_v7().as_bytes().to_vec(),
        session_id: session.id,
        profile_id: profile.id,
        client_id: installation.client.client_id.clone(),
        scopes: vec!["openid".into()],
        resource: installation.resource.id,
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
        revoked: false,
        replaced_by: None,
        family_id: family,
        grace_expires_at: None,
        dpop_jkt: None,
    };
    let family = Uuid::now_v7();
    let first = token(family);
    source
        .redeem_auth_code(&code.code_hash, &session, &first, ctx())
        .await
        .unwrap();
    source
        .rotate_refresh_token(
            first.id,
            &token(family),
            Utc::now() + Duration::seconds(30),
            ctx(),
        )
        .await
        .unwrap();
    let generation = |n: u8| NativeGeneration {
        id: Uuid::now_v7(),
        session_id: session.id,
        key_jkt: "jkt".into(),
        credential_hashes: vec![vec![n; 32]],
        expires_at: Utc::now() + Duration::days(30),
        created_at: Utc::now(),
    };
    let current = generation(1);
    source
        .issue_native_generation(&current, ctx())
        .await
        .unwrap();
    source
        .rotate_native_generation(
            NativeRotation {
                presented: current.id,
                exchange: NativeExchange::from_bytes(&[7; 16]).unwrap(),
                successor: &generation(2),
                sealed: b"sealed",
                redeliver_until: Utc::now() + Duration::seconds(30),
            },
            ctx(),
        )
        .await
        .unwrap();
    profile
}

/// A self-registered profile: its email contact and principal with the
/// claim linking them, a TOTP credential, a second phone contact and a
/// passkey user handle.
async fn registered(source: &SqliteBackend) -> Profile {
    let profile = Profile::new(Some("registered"));
    let credential = Credential::new(profile.id, CredentialType::Totp, vec![7; 32], None);
    let registration = NewRegistration::new(
        profile.clone(),
        SignupIdentifier::Email {
            key: "registered@sid.example.com",
            address: "registered@sid.example.com",
            revision: INSTALLATION_EMAIL_POLICY_REVISION,
        },
        Some(credential),
    )
    .unwrap();
    source.register_profile(&registration, ctx()).await.unwrap();
    let now = Utc::now();
    source
        .create_profile_phone(
            &ProfilePhone {
                id: ProfilePhoneId::new(),
                profile_id: profile.id,
                e164: 12125551234,
                extension: Some(5678),
                label: PhoneLabel::Work,
                custom_label: None,
                is_primary: true,
                can_receive_sms: false,
                can_receive_fax: false,
                can_receive_voice: true,
                verified: true,
                verified_at: Some(now),
                created_at: now,
                updated_at: now,
            },
            ctx(),
        )
        .await
        .unwrap();
    source
        .ensure_webauthn_user_handle(
            profile.id,
            "sid.example.com",
            WebAuthnUserHandle([9; 16]),
            ctx(),
        )
        .await
        .unwrap();
    profile
}

/// The directory around `profile`: a project created by a keyed command,
/// roles with administrative assignments, a group with a member, metadata,
/// a device with its key binding, a pairwise binding, a closure request, an
/// export job and an identifier a keyed creation bound.
async fn directory(source: &SqliteBackend, profile: &Profile) {
    let completion = OperationCompletion::new(
        "profile:coverage",
        OperationKey::parse("create-project").unwrap(),
        "sid.v1.ProjectService/CreateProject",
        b"inputs",
        b"result".to_vec(),
    );
    let project = Project::new("Coverage", Some(profile.id));
    source
        .create_project(&project, ctx().with_operation(completion))
        .await
        .unwrap();
    source
        .bind_operation_resource(&OperationResourceBinding {
            namespace: "profile:coverage".into(),
            key: OperationKey::parse("create-org").unwrap(),
            method: "sid.v1.OrgService/CreateOrg".into(),
            fingerprint: operation::fingerprint(b"inputs"),
            period: None,
            resource: Uuid::now_v7(),
        })
        .await
        .unwrap();

    let mut editor = Role::new(project.id, "editor", "Editor");
    editor.permissions = vec!["documents:read".into()];
    source.create_role(&editor, ctx()).await.unwrap();
    let administrator = Role::new(project.id, "admins", "Admins");
    source.create_role(&administrator, ctx()).await.unwrap();
    // Managed by a profile created after it: the export lists it first.
    let mut delegate = Profile::new(Some("delegate"));
    source.create_profile(&delegate, ctx()).await.unwrap();
    let manager = Profile::new(Some("manager"));
    source.create_profile(&manager, ctx()).await.unwrap();
    delegate.manager_id = Some(manager.id);
    assert!(source.update_profile(&delegate, ctx()).await.unwrap());
    let envelope = AdminEnvelope {
        operations: [AdminOperation::Assign, AdminOperation::Redelegate].into(),
        roles: [editor.id].into(),
        permission_ceiling: ["documents:read".to_string()].into(),
        recipient_kinds: [RecipientKind::Profile].into(),
        recipient_group: None,
        max_validity_secs: 86_400,
    };
    let mut root = RoleAssignment::new(
        RoleAssignmentPrincipal::Profile(profile.id),
        administrator.id,
    )
    .administering(envelope.clone())
    .granted(AssignmentProvenance {
        granted_by: "user:admin".into(),
        basis: None,
        depends_on: None,
        ceiling: None,
    });
    root.policy_admin = Some(PolicyAuthority {
        operations: [PolicyOperation::Read, PolicyOperation::Edit].into(),
    });
    let worked = RoleAssignment::new(RoleAssignmentPrincipal::Profile(delegate.id), editor.id)
        .granted(AssignmentProvenance {
            granted_by: format!("user:{}", profile.id),
            basis: Some(root.id),
            depends_on: None,
            ceiling: Some(envelope.permission_ceiling.clone()),
        });
    for assignment in [&root, &worked] {
        source
            .create_role_assignment(assignment, ctx())
            .await
            .unwrap();
    }
    let group = Group::new(project.id, "readers");
    source.create_group(&group, ctx()).await.unwrap();
    source
        .add_to_group(&GroupMember::new(group.id, delegate.id), ctx())
        .await
        .unwrap();

    source
        .set_profile_metadata(
            &ProfileMetadata::new(profile.id, "team", serde_json::json!("core")),
            ctx(),
        )
        .await
        .unwrap();
    let device = Device::new(profile.id, DeviceType::Mobile);
    source.create_device(&device, ctx()).await.unwrap();
    source
        .import_device_attestation(
            &DeviceAttestation::new_ce(
                device.id,
                profile.id,
                DeviceAttestationFormat::None,
                KeyStorageType::Software,
                "{\"kty\":\"OKP\",\"x\":\"coverage\"}".into(),
            ),
            ctx(),
        )
        .await
        .unwrap();
    source
        .service_binding(
            profile.id,
            &BindingScope::try_from("org-coverage".to_string()).unwrap(),
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_closure_request(
            &ClosureRequest::new(delegate.id, ClosureMode::Voluntary, delegate.id),
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_export_job(&ExportJob::new(profile.id, ExportFormat::Json), ctx())
        .await
        .unwrap();
}

/// The installation's integrations: a machine user with a credential and an
/// impersonation grant, a personal access token, an upstream provider with
/// a linked identity, an initial access token and a SCIM target with a
/// synchronized record and a dead letter.
async fn integrations(source: &SqliteBackend, profile: &Profile) {
    let machine = MachineUser::new(ProjectId::SYSTEM, "ci", "CI", MachineOwner::System);
    source.create_machine_user(&machine, ctx()).await.unwrap();
    source
        .add_machine_credential(
            &MachineUserCredential::new(
                machine.id,
                "kid-ci",
                MachineCredentialType::ClientSecret,
                "hash",
            ),
            None,
            ctx(),
        )
        .await
        .unwrap();
    source
        .save_impersonation_grant(
            &ImpersonationGrant::new(
                machine.id,
                ImpersonationTargetType::User,
                profile.id.to_string(),
                vec!["openid".into()],
            ),
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_pat(
            &PersonalAccessToken::new(
                profile.id,
                "cli",
                "pat-hash",
                "sid_pat_",
                vec!["openid".into()],
            ),
            None,
            ctx(),
        )
        .await
        .unwrap();
    let provider = UpstreamProvider::new(
        "corporate-idp",
        UpstreamProtocol::Oidc,
        "client",
        sid_keys::EncryptedField {
            ciphertext: vec![7; 32],
            nonce: [3; 12],
            key_version: 1,
            context: "upstream:coverage".into(),
        },
    );
    source
        .create_upstream_provider(&provider, ctx())
        .await
        .unwrap();
    source
        .create_upstream_identity(
            &UpstreamIdentity::new(profile.id, provider.id, "upstream-subject"),
            ctx(),
        )
        .await
        .unwrap();
    let now = Utc::now();
    source
        .create_initial_access_token(
            &InitialAccessToken {
                id: InitialAccessTokenId::generate(),
                token_hash: Uuid::now_v7().as_bytes().to_vec(),
                project_id: ProjectId::SYSTEM,
                max_clients: 3,
                clients_registered: 0,
                allowed_scopes: vec!["openid".into()],
                allowed_grant_types: vec!["authorization_code".into()],
                allowed_redirect_patterns: vec!["https://app.sid.example.com/*".into()],
                created_by: profile.id,
                revoked: false,
                expires_at: now + Duration::days(1),
                created_at: now,
            },
            ctx(),
        )
        .await
        .unwrap();
    let target = ScimOutboundTarget {
        id: ScimOutboundTargetId::new(),
        client_id: "downstream-app".into(),
        project_id: ProjectId::SYSTEM,
        display_name: "Downstream".into(),
        endpoint_url: "https://scim.sid.example.com/v2".into(),
        auth: OutboundAuthConfig::Bearer {
            token_secret: "sealed-token".into(),
        },
        attribute_mapping: AttributeMapping::default(),
        group_push: GroupPushConfig::default(),
        sync_config: OutboundSyncConfig::default(),
        enabled: true,
        created_at: now,
        updated_at: now,
    };
    source
        .create_scim_outbound_target(&target, ctx())
        .await
        .unwrap();
    let entity = *profile.id.as_uuid();
    source
        .record_scim_outbound_sync(
            &ScimOutboundRecord {
                target_id: target.id,
                sid_entity_id: entity,
                entity_type: OutboundEntityType::User,
                downstream_id: "ext-42".into(),
                last_synced_at: now,
                last_error: None,
                failure_count: 0,
                created_at: now,
                updated_at: now,
            },
            ctx(),
        )
        .await
        .unwrap();
    source
        .record_scim_outbound_dead_letter(
            &OutboundDlqEntry {
                id: Uuid::now_v7(),
                target_id: target.id,
                event_type: "sid.scim.user.updated.v1".into(),
                payload: serde_json::json!({ "profile_id": entity }),
                sid_entity_id: entity,
                entity_type: OutboundEntityType::User,
                error: "503".into(),
                attempts: 3,
                first_attempt: now,
                last_attempt: now,
            },
            ctx(),
        )
        .await
        .unwrap();
}

/// What the installation keeps for its projects and sign-ins in flight: a
/// branding draft, a Cedar policy, a profile grant, a pending device code,
/// a pending magic link and a quarantined released principal.
async fn settings(source: &SqliteBackend, installation: &Installation, profile: &Profile) {
    use chrono::Timelike;
    // Below the stores' microseconds, as a host clock may report it.
    let now = Utc::now()
        .with_nanosecond(123_456_789)
        .expect("a nanosecond within the second");
    source
        .create_branding_config(
            &BrandingConfig {
                id: BrandingConfigId::generate(),
                project_id: ProjectId::SYSTEM,
                status: BrandingStatus::Draft,
                assets: Default::default(),
                tokens: Default::default(),
                dark_mode: Default::default(),
                text: Default::default(),
                revision: 0,
                created_at: now,
                updated_at: now,
            },
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_cedar_policy(
            &CedarPolicy::new(
                PolicyScope::Project(ProjectId::SYSTEM),
                "readers",
                "permit(principal, action, resource);",
                PolicyEffect::Permit,
            ),
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_profile_grant(
            &ProfileGrant::new(ProjectId::SYSTEM, profile.id, vec!["reader".into()]),
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_device_auth_code(
            &DeviceAuthorizationCode::new(
                installation.client.client_id.clone(),
                Uuid::now_v7().as_bytes().to_vec(),
                "WDJB-MJHT".to_string(),
                Some("openid".to_string()),
                installation.resource.id,
                ProjectId::SYSTEM,
            ),
            ctx(),
        )
        .await
        .unwrap();
    // A code redeemed into a session that has expired since: the code names
    // the session, so the session moves with it.
    let ended = Session::new(profile.id, None, now - Duration::hours(1));
    source.create_session(&ended, ctx()).await.unwrap();
    let mut redeemed = DeviceAuthorizationCode::new(
        installation.client.client_id.clone(),
        Uuid::now_v7().as_bytes().to_vec(),
        "QWER-TYUP".to_string(),
        Some("openid".to_string()),
        installation.resource.id,
        ProjectId::SYSTEM,
    );
    redeemed.status = DeviceAuthStatus::Redeemed;
    redeemed.authorized_by = Some(profile.id);
    redeemed.authorized_at = Some(now - Duration::hours(2));
    redeemed.redeemed_session_id = Some(ended.id);
    source
        .create_device_auth_code(&redeemed, ctx())
        .await
        .unwrap();
    let mut link = MagicLinkSession::new(
        "registered@sid.example.com",
        "registered@sid.example.com",
        "hash-link".into(),
    );
    link.sealed_token = vec![7, 7, 7];
    source
        .create_magic_link_session(&link, ctx())
        .await
        .unwrap();
    source
        .quarantine_principal("released-hash", "email", now + Duration::days(30), ctx())
        .await
        .unwrap();
}

/// What the installation records about its users' activity and its own
/// rules: an invite-only enrollment policy and a registration it admitted by
/// invite (the redemption and the source with it), a consent with a claim
/// grant, notification preferences, a flow configuration with an action, a
/// pending access request, a reset session, an allowlist entry, learned IP
/// reputation, an anomaly event, a sign-in location, a provisioning
/// connector with its credential, an advanced login policy epoch, central
/// management, ceremony state and an attempt count. An email key disposition
/// is stored directly: the policy transition that writes one is not part of
/// this build.
async fn activity(source: &SqliteBackend, installation: &Installation, profile: &Profile) {
    use sid_plugin::{CeremonyStateStore, SignInHistoryStore};
    let now = Utc::now();
    source
        .set_enrollment_policy(
            &EnrollmentPolicy {
                mode: EnrollmentMode::InviteOnly,
                invite: InviteConfig {
                    default_max_uses: 1,
                    default_expiry_hours: 72,
                },
                allowed_domains: vec![],
                track_source: true,
            },
            ModeWrite::Replace,
            ctx(),
        )
        .await
        .unwrap();
    let invite = Invite {
        id: InviteId::generate(),
        code: generate_invite_code(),
        created_by: InviteCreator::Profile(profile.id),
        created_by_name: "coverage".into(),
        metadata: Default::default(),
        max_uses: 2,
        use_count: 0,
        expires_at: Some(now + Duration::days(7)),
        active: true,
        created_at: now,
    };
    source
        .create_invites(std::slice::from_ref(&invite), ctx())
        .await
        .unwrap();
    let invited = Profile::new(Some("invited"));
    let registration = NewRegistration::new(
        invited.clone(),
        SignupIdentifier::Email {
            key: "invited@sid.example.com",
            address: "invited@sid.example.com",
            revision: INSTALLATION_EMAIL_POLICY_REVISION,
        },
        None,
    )
    .unwrap()
    .admitted_by(EnrollmentGate {
        pinned: None,
        email: Some("invited@sid.example.com".into()),
        invite_code: Some(invite.code.clone()),
    });
    source.register_profile(&registration, ctx()).await.unwrap();

    let mut consent = ConsentRecord::new(profile.id, installation.client.client_id.clone());
    consent.status = ConsentStatus::Active;
    consent.grant_claim("email", ClaimType::Data);
    source.create_consent(&consent, ctx()).await.unwrap();
    source
        .save_notification_preferences(&NotificationPreferences::defaults(profile.id), ctx())
        .await
        .unwrap();
    source
        .save_flow_config(
            &FlowConfig {
                project_id: ProjectId::SYSTEM,
                flow_type: FlowType::Authentication,
                steps: Default::default(),
                timeout_seconds: 300,
                updated_at: now,
            },
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_flow_action(
            &FlowAction {
                id: FlowActionId::generate(),
                project_id: ProjectId::SYSTEM,
                flow_type: FlowType::Authentication,
                action_point: ActionPoint::PostLogin,
                name: "notify".into(),
                action_type: ActionType::Webhook,
                config: ActionConfig::Webhook {
                    url: "https://hooks.sid.example.com/login".into(),
                    timeout_seconds: 5,
                    retry_count: 0,
                    headers: Default::default(),
                },
                order: 0,
                on_error: ActionOnError::Continue,
                enabled: true,
                revision: 0,
                created_at: now,
                updated_at: now,
            },
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_access_request(
            &AccessRequest::new(profile.id, ProjectId::SYSTEM, "editor"),
            ctx(),
        )
        .await
        .unwrap();
    source
        .create_reset_session(
            &PasswordResetSession::new(
                profile.id,
                "coverage@sid.example.com".into(),
                "coverage@sid.example.com".into(),
                "reset-hash".into(),
            ),
            ctx(),
        )
        .await
        .unwrap();
    source
        .add_ip_allowlist_entry("10.0.0.0/8", "office", ctx())
        .await
        .unwrap();
    source
        .record_ip_reputation_event("203.0.113.7", false)
        .await
        .unwrap();
    source
        .save_anomaly_event(&AnomalyEventRecord::new(
            "brute_force",
            profile.id.to_string(),
            Some("203.0.113.7".parse().unwrap()),
            "five failures",
            40,
            "step_up",
        ))
        .await
        .unwrap();
    source
        .record_login_location(profile.id, "UA", 50.45, 30.52, 3)
        .await
        .unwrap();
    let org = source.instance_organization().await.unwrap().unwrap();
    let connector = ProvisioningConnector::new(org.id, ProvisioningDirection::Inbound, "Directory");
    source
        .create_provisioning_connector(&connector, ctx())
        .await
        .unwrap();
    assert!(
        source
            .add_provisioning_credential(
                &ProvisioningCredential::new(
                    connector.id,
                    ConnectorCredentialKind::ScimBearer,
                    "a".repeat(64),
                ),
                ctx(),
            )
            .await
            .unwrap()
    );
    // A role the connector holds: its revision counts the grant, and the
    // restored connector keeps that revision.
    let provisioner = Role::new(ProjectId::SYSTEM, "provisioner", "Provisioner");
    source.create_role(&provisioner, ctx()).await.unwrap();
    source
        .create_role_assignment(
            &RoleAssignment::new(
                RoleAssignmentPrincipal::ProvisioningConnector(connector.id),
                provisioner.id,
            ),
            ctx(),
        )
        .await
        .unwrap();
    let mut tx = SqliteBackend::begin_write_on(source.pool()).await.unwrap();
    SqliteBackend::advance_login_policy_epoch(&mut tx)
        .await
        .unwrap();
    SqliteBackend::commit_mutation(tx, "installation:login_policy", ctx())
        .await
        .unwrap();
    assert_eq!(
        source.adopt_central_management(ctx()).await.unwrap(),
        CentralAdoption::Adopted
    );
    source
        .put_ceremony_state(
            "webauthn",
            "challenge",
            b"pending",
            std::time::Duration::from_secs(300),
        )
        .await
        .unwrap();
    source
        .count_in_window(
            "login_attempts",
            "coverage",
            std::time::Duration::from_secs(900),
        )
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO email_policy_dispositions
             (principal_id, from_revision, to_revision, disposition, reason)
         SELECT id, email_policy_revision, email_policy_revision, 'migrated', 'coverage'
         FROM principals WHERE value = 'registered@sid.example.com'",
    )
    .execute(source.pool())
    .await
    .unwrap();
}

/// The installation's key material and owed work: field key versions, the
/// sealed OPAQUE setup, a password changed under a recorded history with the
/// evaluator's sealed key and its own key version, an issued operation
/// period and owed durable work.
async fn history(source: &SqliteBackend) {
    use sid_plugin::history_keys::HistoryKeyStore;
    let org = source.instance_organization().await.unwrap().unwrap();
    let profile = Profile::new(Some("history"));
    source.create_profile(&profile, ctx()).await.unwrap();
    source
        .insert_key_version(
            &sid_keys::KeyVersionParams::new(1, vec![1; 16], "key-v1"),
            ctx(),
        )
        .await
        .unwrap();
    let keys = source.history_keys();
    keys.insert_key_version(
        &sid_keys::KeyVersionParams::new(1, vec![6; 16], "history-v1"),
        AuditEntry::system("test", "history"),
    )
    .await
    .unwrap();
    let owner_domain = sid_authn::password_history::owner_domain(org.id.as_bytes(), profile.id);
    let new_epoch = |owner_domain: [u8; 32]| {
        let id = HistoryEpochId::generate();
        NewKeyEpoch {
            epoch: KeyEpoch {
                id,
                owner_domain,
                suite: HistorySuite::PallasPoseidonV1,
                public_key: {
                    use group::{Curve, Group, GroupEncoding};
                    pasta_curves::pallas::Point::generator()
                        .to_affine()
                        .to_bytes()
                },
                ksf: HistoryKsf::DEFAULT,
                ksf_salt: [4; 32],
                status: HistoryEpochUse::Active,
                created_at: Utc::now().trunc_subsecs(3),
            },
            key: WrappedHistoryKey(
                sid_keys::EncryptedField {
                    key_version: 1,
                    nonce: [0; 12],
                    context: history_key_context(id, &owner_domain),
                    ciphertext: vec![5; 48],
                }
                .to_bytes(),
            ),
        }
    };
    let epoch = new_epoch(owner_domain);
    keys.create_first_epoch(
        &epoch,
        Uuid::now_v7(),
        AuditEntry::system("test", "history"),
    )
    .await
    .unwrap();
    let field_keys = sid_keys::SoftwareKeyManager::new(
        secrecy::SecretBox::new(Box::new([9; 32])),
        source.list_key_versions().await.unwrap(),
        std::sync::Arc::new(sid_crypto::RustCryptoPrimitives::new()),
    )
    .unwrap();
    sid_authn::opaque::server_setup::load_or_create(
        source,
        &field_keys,
        &sid_authn::opaque::PallasOpaque::new(),
    )
    .await
    .unwrap();
    let password = Credential::new(profile.id, CredentialType::Opaque, b"before".to_vec(), None);
    source.create_credential(&password, ctx()).await.unwrap();
    let mut changed = password.clone();
    changed.data = CredentialData::new(b"after".to_vec());
    let commit = HistoryCommit {
        owner: profile.id,
        expected_revision: source
            .get_password_history(profile.id)
            .await
            .unwrap()
            .revision,
        epochs: vec![epoch.epoch.descriptor()],
        entries: vec![(epoch.epoch.id, [9; 32])],
        evidence: HistoryEvidence {
            operation: Uuid::now_v7(),
            policy_version: 1,
        },
        depth: 24,
        max_age_days: 0,
    };
    assert!(
        source
            .change_password(password.id, b"before", &changed, Some(&commit), ctx())
            .await
            .unwrap()
    );
    // The evaluator's lifecycle: the key replaced at the committed revision,
    // a preparation in flight that recorded its live set and uses, an
    // aborted first enrollment's fence and a purged owner's.
    let key_audit = || AuditEntry::system("test", "history");
    let revision = source
        .get_password_history(profile.id)
        .await
        .unwrap()
        .revision;
    let mut successor = new_epoch(owner_domain);
    successor.epoch.created_at = epoch.epoch.created_at + Duration::milliseconds(1);
    keys.rotate_epoch(&successor, epoch.epoch.id, revision, key_audit())
        .await
        .unwrap();
    let now = Utc::now();
    keys.prepare_epochs(
        &HistoryPreparation {
            owner_domain,
            live: HistoryLiveSet {
                revision,
                live: vec![epoch.epoch.id],
                settled: vec![],
            },
            operation: Uuid::now_v7(),
            expires_at: now + Duration::minutes(10),
            now,
        },
        key_audit(),
    )
    .await
    .unwrap();
    keys.abandon_enrollment(&[8; 32], Uuid::now_v7(), key_audit())
        .await
        .unwrap();
    keys.purge_owner(&[9; 32], key_audit()).await.unwrap();

    source
        .current_operation_period(Utc::now(), Duration::hours(1))
        .await
        .unwrap();
    source
        .create_profile(
            &Profile::new(Some("owed")),
            ctx().with_work(NewWork::new(
                WorkKind::new("sid.coverage.owed").unwrap(),
                b"payload".to_vec(),
            )),
        )
        .await
        .unwrap();
}

/// A source holding rows in every moved table.
async fn populated() -> SqliteBackend {
    let source = SqliteBackend::new_in_memory().await.unwrap();
    let installation = installation(&source).await;
    // Retention cut the oldest records: the chains resume from checkpoints.
    assert!(
        source
            .drop_expired_audit_records(Utc::now() + Duration::days(62), ctx())
            .await
            .unwrap()
            > 0
    );
    let profile = signed_in(&source, &installation).await;
    registered(&source).await;
    directory(&source, &profile).await;
    integrations(&source, &profile).await;
    settings(&source, &installation, &profile).await;
    history(&source).await;
    activity(&source, &installation, &profile).await;
    source
}

// A table the source holds rows in and the target lacks after the move is
// state a restore loses; a moved table the source leaves empty is one this
// test does not prove, so the fixture must reach it.
#[tokio::test]
async fn every_table_moves_with_the_snapshot() {
    let source = populated().await;
    let (source_audit, source_keys) = (
        SqliteAuditLog::new(source.pool().clone()),
        source.history_keys(),
    );
    let source_store = snapshot::Store {
        storage: &source,
        audit: &source_audit,
        history_keys: &source_keys,
    };
    let snapshot = snapshot::export(source_store, &AuthnSnapshotRules)
        .await
        .unwrap();
    let target = SqliteBackend::new_in_memory().await.unwrap();
    let (target_audit, target_keys) = (
        SqliteAuditLog::new(target.pool().clone()),
        target.history_keys(),
    );
    let target_store = snapshot::Store {
        storage: &target,
        audit: &target_audit,
        history_keys: &target_keys,
    };
    snapshot::import(
        target_store,
        &AuthnSnapshotRules,
        &sid_crypto::RustCryptoPrimitives::new(),
        &snapshot,
    )
    .await
    .unwrap();
    // An import interrupted anywhere resumes: importing the same archive
    // again finds every record already restored and adds nothing.
    let repeated = snapshot::import(
        target_store,
        &AuthnSnapshotRules,
        &sid_crypto::RustCryptoPrimitives::new(),
        &snapshot,
    )
    .await
    .unwrap();
    assert_eq!(repeated.total(), 0, "{repeated}");
    let verified = snapshot::verify(source_store, target_store, &AuthnSnapshotRules)
        .await
        .unwrap();
    assert!(verified.passed, "{verified}");

    let before = rows(&source).await;
    let after = rows(&target).await;
    let mut unproved = Vec::new();
    let mut lost = Vec::new();
    for (table, held) in &before {
        if NOT_MOVED.iter().any(|(t, _)| t == table) {
            continue;
        }
        if held.is_empty() {
            unproved.push(table.as_str());
            continue;
        }
        if ADVANCED.iter().any(|(t, _)| t == table) {
            continue;
        }
        let moved = after.get(table).cloned().unwrap_or_default();
        let missing: Vec<_> = held.iter().filter(|r| !moved.contains(r)).collect();
        // The import's own audit records continue the chains it moved.
        let added: Vec<_> = if CONTINUED.iter().any(|(t, _)| t == table) {
            Vec::new()
        } else {
            moved.iter().filter(|r| !held.contains(r)).collect()
        };
        if !missing.is_empty() || !added.is_empty() {
            lost.push(format!(
                "{table}: missing {missing:?}, not in the source {added:?}"
            ));
        }
    }
    assert!(
        lost.is_empty() && unproved.is_empty(),
        "rows a move loses: {lost:#?}\ntables the fixture leaves empty: {unproved:#?}"
    );
}
