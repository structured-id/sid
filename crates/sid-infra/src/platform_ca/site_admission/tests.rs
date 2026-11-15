use super::*;

fn refusal(reason: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "code": 9,
        "message": "refused",
        "details": [{
            "@type": "type.googleapis.com/google.rpc.ErrorInfo",
            "reason": reason,
            "domain": "sid.example.com",
        }],
    }))
    .unwrap()
}

// The platform's answers read as the publication needs them: taken, a
// newer revision already standing (nothing left to deliver), a platform
// that is away or does not serve the route yet (ask again), and a refusal
// of the statement itself (final). Bug prevented: a superseded statement
// retried for two weeks, or an unreachable platform read as a final refusal
// that drops the delivery.
#[test]
fn answers_read_as_the_publication_needs_them() {
    use reqwest::StatusCode;
    assert_eq!(answer(StatusCode::OK, b"{}").unwrap(), Published::Held);
    assert_eq!(
        answer(StatusCode::BAD_REQUEST, &refusal(SUPERSEDED)).unwrap(),
        Published::Superseded
    );
    for away in [
        StatusCode::SERVICE_UNAVAILABLE,
        StatusCode::BAD_GATEWAY,
        StatusCode::TOO_MANY_REQUESTS,
        StatusCode::NOT_FOUND,
    ] {
        assert!(
            matches!(answer(away, b""), Err(PublishError::Unavailable(_))),
            "{away}"
        );
    }
    for refused in [
        "SITE_ADMISSION_NOT_AUTHENTIC",
        "SITE_ADMISSION_REVISION_CONFLICT",
    ] {
        assert!(matches!(
            answer(StatusCode::FORBIDDEN, &refusal(refused)),
            Err(PublishError::Refused(why)) if why.contains(refused)
        ));
    }
}

// The endpoint is the platform's public API route, under its origin, and
// only over https.
#[test]
fn the_endpoint_is_under_the_platforms_api() {
    assert_eq!(
        endpoint_of(&url::Url::parse("https://sid.example.com").unwrap())
            .unwrap()
            .as_str(),
        "https://sid.example.com/api/v1/federation/site-admissions"
    );
    assert!(endpoint_of(&url::Url::parse("http://sid.example.com").unwrap()).is_err());
}
