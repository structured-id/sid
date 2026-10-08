use super::*;
use sid_plugin::notification::NotificationPriority;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn test_endpoint() -> WebhookEndpoint {
    WebhookEndpoint {
        url: "https://sid.example.com/webhook".into(),
        secret: "test-secret-key".into(),
        headers: vec![],
        active: true,
    }
}

fn test_recipient() -> Recipient {
    Recipient {
        profile_id: "prof_123".into(),
        email: None,
        phone: None,
        push_endpoint: None,
        device_token: None,
        locale: "en".into(),
    }
}

fn test_message() -> RenderedMessage {
    RenderedMessage {
        subject: None,
        body: r#"{"event":"test"}"#.into(),
        body_text: None,
        priority: NotificationPriority::Critical,
        event_type: "sid.security.brute_force.v1".into(),
    }
}

/// One request an endpoint received: lower-case headers and the body.
struct Received {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Received {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// An endpoint on localhost answering one request with `status`; the
/// request it received comes back through the handle.
async fn endpoint_answering(status: u16) -> (String, tokio::task::JoinHandle<Received>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    let handle = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        let (head_end, content_length) = loop {
            let n = socket.read(&mut buf).await.unwrap();
            raw.extend_from_slice(&buf[..n]);
            if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&raw[..pos]).to_string();
                let length = head
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                break (pos + 4, length);
            }
        };
        while raw.len() < head_end + content_length {
            let n = socket.read(&mut buf).await.unwrap();
            raw.extend_from_slice(&buf[..n]);
        }
        let head = String::from_utf8_lossy(&raw[..head_end]).to_string();
        let headers = head
            .lines()
            .skip(1)
            .filter_map(|l| l.split_once(':'))
            .map(|(n, v)| (n.trim().to_ascii_lowercase(), v.trim().to_string()))
            .collect();
        let response =
            format!("HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
        socket.write_all(response.as_bytes()).await.unwrap();
        Received {
            headers,
            body: raw[head_end..head_end + content_length].to_vec(),
        }
    });
    (url, handle)
}

fn channel(endpoints: Vec<WebhookEndpoint>) -> WebhookChannel {
    WebhookChannel::new(endpoints).unwrap()
}

fn endpoint_at(url: String) -> WebhookEndpoint {
    WebhookEndpoint {
        url,
        secret: "test-secret-key".into(),
        headers: vec![("x-crm-token".into(), "crm-1".into())],
        active: true,
    }
}

#[test]
fn test_hmac_sign() {
    let sig = WebhookChannel::sign("secret", b"payload");
    assert!(!sig.is_empty());
    assert_eq!(sig.len(), 64); // SHA-256 hex = 64 chars
}

#[test]
fn test_hmac_verify_valid() {
    let sig = WebhookChannel::sign("secret", b"payload");
    assert!(WebhookChannel::verify("secret", b"payload", &sig));
}

#[test]
fn test_hmac_verify_invalid() {
    let sig = WebhookChannel::sign("secret", b"payload");
    assert!(!WebhookChannel::verify("wrong-secret", b"payload", &sig));
    assert!(!WebhookChannel::verify("secret", b"tampered", &sig));
}

#[test]
fn test_hmac_verify_wrong_length() {
    assert!(!WebhookChannel::verify("secret", b"payload", "short"));
}

/// A delivery is an HTTP POST of the message, signed over the exact body
/// (`X-SID-Signature: sha256=<hmac>`), naming the event and the delivery,
/// with the endpoint's own headers; a 2xx answer is the receipt.
#[tokio::test]
async fn test_webhook_posts_signed_message() {
    let (url, received) = endpoint_answering(204).await;
    let channel = channel(vec![endpoint_at(url)]);

    let receipt = channel
        .deliver(&test_recipient(), &test_message())
        .await
        .unwrap();
    let request = received.await.unwrap();

    assert_eq!(receipt.channel, "webhook");
    let signature = request
        .header("x-sid-signature")
        .and_then(|s| s.strip_prefix("sha256="))
        .expect("signature header");
    assert!(WebhookChannel::verify(
        "test-secret-key",
        &request.body,
        signature
    ));
    assert_eq!(
        request.header("x-sid-event"),
        Some("sid.security.brute_force.v1")
    );
    assert_eq!(
        request.header("x-sid-delivery"),
        Some(receipt.message_id.as_str())
    );
    assert_eq!(request.header("x-crm-token"), Some("crm-1"));
    assert_eq!(request.header("content-type"), Some("application/json"));
}

/// An endpoint that fails with 5xx has not accepted the message: the
/// delivery fails (and is retried) instead of reporting success.
#[tokio::test]
async fn test_webhook_server_error_fails() {
    let (url, received) = endpoint_answering(503).await;
    let channel = channel(vec![endpoint_at(url)]);

    let err = channel
        .deliver(&test_recipient(), &test_message())
        .await
        .unwrap_err();
    received.await.unwrap();

    assert!(matches!(err, DeliveryError::Failed(_)), "{err:?}");
}

/// A 4xx answer (other than 408/429) refuses the message permanently.
#[tokio::test]
async fn test_webhook_client_error_rejects() {
    let (url, received) = endpoint_answering(410).await;
    let channel = channel(vec![endpoint_at(url)]);

    let err = channel
        .deliver(&test_recipient(), &test_message())
        .await
        .unwrap_err();
    received.await.unwrap();

    assert!(matches!(err, DeliveryError::Rejected(_)), "{err:?}");
}

/// 429 asks the sender to slow down: the delivery is retried later.
#[tokio::test]
async fn test_webhook_too_many_requests_is_rate_limited() {
    let (url, received) = endpoint_answering(429).await;
    let channel = channel(vec![endpoint_at(url)]);

    let err = channel
        .deliver(&test_recipient(), &test_message())
        .await
        .unwrap_err();
    received.await.unwrap();

    assert!(matches!(err, DeliveryError::RateLimited), "{err:?}");
}

/// Every endpoint is tried, and one that can still succeed on retry decides
/// the delivery over one that refused: a refusal elsewhere must not drop the
/// message for the endpoint that was only temporarily down.
#[tokio::test]
async fn test_webhook_retryable_endpoint_outranks_refusing_one() {
    let (refusing, refused) = endpoint_answering(410).await;
    let (down, failed) = endpoint_answering(503).await;
    let (up, accepted) = endpoint_answering(200).await;
    let channel = channel(vec![
        endpoint_at(refusing),
        endpoint_at(down),
        endpoint_at(up),
    ]);

    let err = channel
        .deliver(&test_recipient(), &test_message())
        .await
        .unwrap_err();
    refused.await.unwrap();
    failed.await.unwrap();
    accepted.await.unwrap();

    assert!(matches!(err, DeliveryError::Failed(_)), "{err:?}");
}

/// Nothing listening: the request never reached anyone, so it is a plain
/// failure to retry.
#[tokio::test]
async fn test_webhook_unreachable_fails() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/hook", listener.local_addr().unwrap());
    drop(listener);
    let channel = channel(vec![endpoint_at(url)]);

    let err = channel
        .deliver(&test_recipient(), &test_message())
        .await
        .unwrap_err();

    assert!(matches!(err, DeliveryError::Failed(_)), "{err:?}");
}

#[tokio::test]
async fn test_webhook_no_active_endpoints() {
    let mut endpoint = test_endpoint();
    endpoint.active = false;
    let channel = channel(vec![endpoint]);

    let err = channel
        .deliver(&test_recipient(), &test_message())
        .await
        .unwrap_err();
    assert!(matches!(err, DeliveryError::NotConfigured));
}

#[tokio::test]
async fn test_webhook_health_with_endpoints() {
    let channel = channel(vec![test_endpoint()]);
    let health = channel.health().await.unwrap();
    assert!(health.healthy);
}

#[tokio::test]
async fn test_webhook_health_no_endpoints() {
    let channel = channel(vec![]);
    let health = channel.health().await.unwrap();
    assert!(!health.healthy);
}

#[test]
fn test_webhook_channel_id() {
    let channel = channel(vec![]);
    assert_eq!(channel.channel_id(), "webhook");
}

#[test]
fn test_hmac_deterministic() {
    let sig1 = WebhookChannel::sign("key", b"data");
    let sig2 = WebhookChannel::sign("key", b"data");
    assert_eq!(sig1, sig2);
}
