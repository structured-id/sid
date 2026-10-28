use super::*;
use chrono::Duration as ChronoDuration;
use sid_core::models::ProfileId;
use sid_core::models::session::Elevation;

fn requirements(min_acr: AuthLevel, enforcement: EnforcementMode) -> LoginRequirements {
    LoginRequirements {
        min_acr,
        required_amr: BTreeSet::new(),
        max_authentication_age: None,
        enforcement,
        fence: None,
    }
}

/// A session authenticated `ago` before now at `level` with `amr`.
fn session(level: AuthLevel, amr: &[&str], ago: ChronoDuration) -> Session {
    let mut session = Session::new(
        ProfileId::generate(),
        "127.0.0.1".to_string(),
        Utc::now() + ChronoDuration::hours(24),
    );
    session.assurance_level = level;
    session.amr = amr.iter().map(|m| (*m).to_string()).collect();
    session.authenticated_at = Utc::now() - ago;
    session
}

fn client(
    required_acr: Option<AuthLevel>,
    required_amr: &[&str],
    mode: EnforcementMode,
) -> OAuth2Client {
    let now = Utc::now();
    let app = sid_core::models::Application {
        id: sid_core::models::ApplicationId::generate(),
        project_id: sid_core::models::ProjectId::system(),
        name: "Orders web".into(),
        system: None,
        revision: 0,
        created_at: now,
        updated_at: now,
    };
    let mut client = crate::test_support::client_of(&app, sid_core::models::OrgId::generate());
    client.required_acr = required_acr;
    client.required_amr = required_amr.iter().map(|m| (*m).to_string()).collect();
    client.enforcement_mode = mode;
    client
}

// A Basic requirement admits a Basic authentication, under hard enforcement
// too.
#[test]
fn a_met_requirement_allows() {
    let r = requirements(AuthLevel::Basic, EnforcementMode::Hard);
    let decision = r.decide(
        &session(AuthLevel::Basic, &["pwd"], ChronoDuration::zero()),
        Utc::now(),
    );
    assert_eq!(
        decision,
        LoginDecision::Allow {
            audited: Unmet::default()
        }
    );
}

// Below the level asks to step up to it, under soft and hard enforcement;
// audit allows and reports what was unmet.
#[test]
fn a_lower_level_steps_up_unless_audited() {
    let s = session(AuthLevel::Basic, &["pwd"], ChronoDuration::zero());
    let unmet = Unmet {
        acr: Some(AuthLevel::Standard),
        ..Unmet::default()
    };
    for mode in [EnforcementMode::Soft, EnforcementMode::Hard] {
        assert_eq!(
            requirements(AuthLevel::Standard, mode).decide(&s, Utc::now()),
            LoginDecision::StepUp(unmet.clone()),
            "{mode:?}"
        );
    }
    assert_eq!(
        requirements(AuthLevel::Standard, EnforcementMode::Audit).decide(&s, Utc::now()),
        LoginDecision::Allow { audited: unmet }
    );
}

// Regression guard: a missing method is named as a method, not folded into a
// level; a Basic requirement with a required method refuses a Basic
// authentication without it.
#[test]
fn a_missing_method_is_named() {
    let mut r = requirements(AuthLevel::Basic, EnforcementMode::Hard);
    r.required_amr.insert("hwk".into());
    let decision = r.decide(
        &session(AuthLevel::Basic, &["pwd"], ChronoDuration::zero()),
        Utc::now(),
    );
    assert_eq!(
        decision,
        LoginDecision::StepUp(Unmet {
            amr: vec!["hwk".into()],
            ..Unmet::default()
        })
    );
    let with_it = session(AuthLevel::Basic, &["pwd", "hwk"], ChronoDuration::zero());
    assert!(matches!(
        r.decide(&with_it, Utc::now()),
        LoginDecision::Allow { .. }
    ));
}

// Regression guard: an authentication older than the age bound is named as
// too old, counted from when it happened; one within it passes. A Basic level
// does not hide it.
#[test]
fn an_old_authentication_is_named() {
    let mut r = requirements(AuthLevel::Basic, EnforcementMode::Hard);
    r.max_authentication_age = Some(Duration::from_secs(300));
    let old = session(AuthLevel::Basic, &["pwd"], ChronoDuration::seconds(600));
    assert_eq!(
        r.decide(&old, Utc::now()),
        LoginDecision::StepUp(Unmet {
            max_authentication_age: Some(Duration::from_secs(300)),
            ..Unmet::default()
        })
    );
    let recent = session(AuthLevel::Basic, &["pwd"], ChronoDuration::seconds(60));
    assert!(matches!(
        r.decide(&recent, Utc::now()),
        LoginDecision::Allow { .. }
    ));
}

// Regression guard: an authentication time in the future proves no age and
// fails an age bound instead of passing it.
#[test]
fn a_future_authentication_time_fails_an_age_bound() {
    let mut r = requirements(AuthLevel::Basic, EnforcementMode::Hard);
    r.max_authentication_age = Some(Duration::from_secs(300));
    let future = session(AuthLevel::Basic, &["pwd"], ChronoDuration::seconds(-120));
    assert!(matches!(
        r.decide(&future, Utc::now()),
        LoginDecision::StepUp(_)
    ));
}

// A step-up counts while it lasts; once lapsed, a requirement that needs it
// asks for a step-up again.
#[test]
fn a_lapsed_step_up_no_longer_counts() {
    let r = requirements(AuthLevel::Elevated, EnforcementMode::Hard);
    let mut s = session(AuthLevel::Standard, &["pwd", "otp"], ChronoDuration::zero());
    s.elevation = Some(Elevation {
        level: AuthLevel::Elevated,
        until: Utc::now() + ChronoDuration::minutes(5),
    });
    assert!(matches!(
        r.decide(&s, Utc::now()),
        LoginDecision::Allow { .. }
    ));
    s.elevation = Some(Elevation {
        level: AuthLevel::Elevated,
        until: Utc::now() - ChronoDuration::seconds(1),
    });
    assert!(matches!(r.decide(&s, Utc::now()), LoginDecision::StepUp(_)));
}

// The client and the request only strengthen: a higher level, more methods,
// a harder enforcement; a weaker client value changes nothing.
#[test]
fn the_client_and_request_only_strengthen() {
    let base = requirements(AuthLevel::Standard, EnforcementMode::Hard);
    let weaker = base.clone().with_client(
        &client(Some(AuthLevel::Basic), &[], EnforcementMode::Audit),
        Some(AuthLevel::Basic),
    );
    assert_eq!(weaker.min_acr, AuthLevel::Standard);
    assert_eq!(weaker.enforcement, EnforcementMode::Hard);

    let stricter = requirements(AuthLevel::Basic, EnforcementMode::Audit).with_client(
        &client(Some(AuthLevel::Standard), &["hwk"], EnforcementMode::Hard),
        Some(AuthLevel::Elevated),
    );
    assert_eq!(stricter.min_acr, AuthLevel::Elevated);
    assert_eq!(stricter.enforcement, EnforcementMode::Hard);
    assert!(stricter.required_amr.contains("hwk"));
}

// A local authentication completing now meets any authentication-age bound,
// however short: it is dated at the decision's own instant, not at a later
// one that would read as an authentication from the future.
#[test]
fn a_local_authentication_completing_now_meets_an_age_bound() {
    let r = LoginRequirements {
        max_authentication_age: Some(Duration::from_secs(1)),
        ..requirements(AuthLevel::Basic, EnforcementMode::Hard)
    };
    let now = Utc::now();
    let probe = local_authentication(
        ProfileId::generate(),
        AuthLevel::Basic,
        &["pwd".to_string()],
        now,
    );
    assert_eq!(probe.authenticated_at, now);
    assert_eq!(
        r.decide(&probe, now),
        LoginDecision::Allow {
            audited: Unmet::default()
        }
    );
}

// The fixed source states the baseline policy's requirements for every
// application, with no fence.
#[tokio::test]
async fn the_fixed_source_states_its_policy() {
    let mut policy = SecurityPolicy::ce_default();
    policy.auth.min_acr = AuthLevel::Standard;
    policy.auth.required_amr = vec!["otp".into()];
    policy.enforcement.mode = EnforcementMode::Hard;
    let source = FixedLoginPolicy::of(&policy);
    for client in [None, Some("a-client")] {
        let r = source.requirements(client).await.unwrap();
        assert_eq!(r.min_acr, AuthLevel::Standard);
        assert_eq!(r.required_amr, BTreeSet::from(["otp".to_string()]));
        assert_eq!(r.max_authentication_age, None);
        assert_eq!(r.enforcement, EnforcementMode::Hard);
        assert_eq!(r.fence, None);
    }
}

// A TOTP code completes a password sign-in that the requirements ask an
// `otp` method and the Standard level of; it does not meet a requirement of
// another method or of a higher level, which the sign-in then cannot
// complete with it.
#[test]
fn a_further_factor_meets_only_what_it_provides() {
    let password = session(AuthLevel::Basic, &["pwd"], ChronoDuration::zero());
    let now = Utc::now();

    let mut otp = requirements(AuthLevel::Standard, EnforcementMode::Hard);
    otp.required_amr.insert("otp".into());
    assert!(otp.met_with(&password, AuthLevel::Standard, "otp", now));

    let mut key = requirements(AuthLevel::Basic, EnforcementMode::Hard);
    key.required_amr.insert("hwk".into());
    assert!(!key.met_with(&password, AuthLevel::Standard, "otp", now));

    let elevated = requirements(AuthLevel::Elevated, EnforcementMode::Hard);
    assert!(!elevated.met_with(&password, AuthLevel::Standard, "otp", now));

    // An authentication too old stays too old after another factor.
    let mut fresh = otp.clone();
    fresh.max_authentication_age = Some(std::time::Duration::from_secs(60));
    let old = session(AuthLevel::Basic, &["pwd"], ChronoDuration::minutes(5));
    assert!(!fresh.met_with(&old, AuthLevel::Standard, "otp", now));
}
