// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use axum::http::Request;
use http_body_util::BodyExt;

const CONFIG: &[u8] =
    br#"{"sidUrl":"https://sid.example.com","environment":"dev","release":"1.2.3"}"#;

/// A bundle laid out as a Quasar SPA build: shell, hashed assets, a root file.
fn bundle_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sid-ui-host-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("assets")).unwrap();
    std::fs::write(
        dir.join("index.html"),
        "<!doctype html><title>shell</title>",
    )
    .unwrap();
    std::fs::write(dir.join("assets/app-abc123.js"), "console.log(1)").unwrap();
    std::fs::write(dir.join("favicon.ico"), "ico").unwrap();
    dir
}

async fn get_path(app: &Router, method: Method, path: &str) -> (StatusCode, Response) {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    (response.status(), response)
}

async fn body(response: Response) -> String {
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn header_of(response: &Response, name: header::HeaderName) -> Option<String> {
    response
        .headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_owned())
}

fn app(name: &str) -> Router {
    router(UiBundle::new(&bundle_dir(name), "/account/", CONFIG).unwrap())
}

/// `path` asked with `If-None-Match: tags`.
async fn get_if_none_match(app: &Router, path: &str, tags: &str) -> Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .header(header::IF_NONE_MATCH, tags)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

/// The configuration is what start-up reads before anything else: served
/// exactly as the deployment generated it, kept by the browser and
/// revalidated on every use, so a change is seen at once.
#[tokio::test]
async fn test_config_is_served_for_revalidation() {
    let (status, response) = get_path(&app("config"), Method::GET, "/account/config.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL).as_deref(),
        Some("no-cache")
    );
    assert_eq!(
        header_of(&response, header::CONTENT_TYPE).as_deref(),
        Some("application/json")
    );
    let tag = header_of(&response, header::ETAG).expect("an ETag");
    assert!(tag.starts_with('"') && tag.ends_with('"'), "{tag}");
    assert_eq!(body(response).await.as_bytes(), CONFIG);
}

/// Regression: the configuration was `no-store`, so every start downloaded
/// it whole. An unchanged configuration now answers 304 with no body, under
/// any form of `If-None-Match` that names it (RFC 9110 §13.1.2: a list, `*`,
/// weak comparison); another tag gets the configuration.
#[tokio::test]
async fn test_unchanged_config_is_not_modified() {
    let app = app("configetag");
    let (_, first) = get_path(&app, Method::GET, "/account/config.json").await;
    let tag = header_of(&first, header::ETAG).expect("an ETag");
    for tags in [
        tag.clone(),
        format!("\"other\", {tag}"),
        format!("W/{tag}"),
        "*".to_owned(),
    ] {
        let response = get_if_none_match(&app, "/account/config.json", &tags).await;
        assert_eq!(response.status(), StatusCode::NOT_MODIFIED, "{tags}");
        assert_eq!(
            header_of(&response, header::ETAG).as_deref(),
            Some(tag.as_str())
        );
        assert_eq!(
            header_of(&response, header::CACHE_CONTROL).as_deref(),
            Some("no-cache")
        );
        assert_eq!(body(response).await, "", "{tags}");
    }
    let response = get_if_none_match(&app, "/account/config.json", "\"other\"").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(body(response).await.as_bytes(), CONFIG);
}

/// Another configuration has another tag, so a change is never answered 304.
#[test]
fn test_config_tag_follows_its_bytes() {
    let dir = bundle_dir("configtags");
    let one = UiBundle::new(&dir, "/account/", CONFIG).unwrap();
    let other = UiBundle::new(
        &dir,
        "/account/",
        br#"{"environment":"dev","release":"1.2.4"}"#,
    )
    .unwrap();
    let tag = |bundle: &UiBundle| bundle.config.borrow().as_ref().unwrap().tag.clone();
    assert_ne!(tag(&one), tag(&other));
}

use sid_proto::sid::v1::identity::PrincipalType;
use sid_proto::sid::v1::ui::PublicUiSettings;

fn projection(revision: u64, registration: &[PrincipalType], minimum: u32) -> PublicUiSettings {
    PublicUiSettings {
        revision,
        registration_principal_types: registration.iter().map(|t| *t as i32).collect(),
        registration_username_min_length: minimum,
        sign_in_principal_types: vec![PrincipalType::Email as i32, PrincipalType::Username as i32],
    }
}

async fn config_json(app: &Router) -> serde_json::Value {
    let (status, response) = get_path(app, Method::GET, "/account/config.json").await;
    assert_eq!(status, StatusCode::OK);
    serde_json::from_slice(body(response).await.as_bytes()).unwrap()
}

/// A live bundle serves the deployment's configuration together with the
/// installation's public settings, only the types a UI field enters, under
/// the names the UI uses; the base stays as the deployment wrote it.
#[tokio::test]
async fn test_live_config_carries_the_settings() {
    let (bundle, sink) = UiBundle::live(&bundle_dir("liveconfig"), "/account/", CONFIG).unwrap();
    let app = router(bundle);
    let mut settings = projection(1, &[PrincipalType::Email, PrincipalType::Username], 6);
    settings.registration_principal_types.extend([
        PrincipalType::NfcTag as i32,
        99,
        PrincipalType::Email as i32,
    ]);
    sink.stream().apply(&settings).unwrap();
    let config = config_json(&app).await;
    assert_eq!(config["environment"], "dev");
    assert_eq!(config["sidUrl"], "https://sid.example.com");
    assert_eq!(
        config["settings"],
        serde_json::json!({
            "registrationPrincipalTypes": ["email", "username"],
            "registrationUsernameMinLength": 6,
            "signInPrincipalTypes": ["email", "username"],
        })
    );
    // Without usernames in registration there is no minimum to state.
    sink.stream()
        .apply(&projection(2, &[PrincipalType::Email], 0))
        .unwrap();
    let config = config_json(&app).await;
    assert_eq!(
        config["settings"]["registrationPrincipalTypes"],
        serde_json::json!(["email"])
    );
    assert!(
        config["settings"]
            .get("registrationUsernameMinLength")
            .is_none()
    );
}

/// Before the first projection there is nothing complete to serve: the
/// configuration and the standalone health answer 503 and nothing is kept,
/// never the deployment's configuration alone as if it were complete.
#[tokio::test]
async fn test_live_config_waits_for_the_first_projection() {
    let (bundle, sink) = UiBundle::live(&bundle_dir("livewait"), "/account/", CONFIG).unwrap();
    let app = standalone(bundle).unwrap();
    let (status, response) = get_path(&app, Method::GET, "/account/config.json").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    let (status, _) = get_path(&app, Method::GET, "/health").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // Static assets do not wait for the settings.
    let (status, _) = get_path(&app, Method::GET, "/account/assets/app-abc123.js").await;
    assert_eq!(status, StatusCode::OK);
    sink.stream()
        .apply(&projection(1, &[PrincipalType::Email], 0))
        .unwrap();
    let (status, _) = get_path(&app, Method::GET, "/health").await;
    assert_eq!(status, StatusCode::OK);
}

/// Within one stream an older or repeated revision is not served; an
/// unusable projection is refused and the served one stays.
#[tokio::test]
async fn test_stale_and_unusable_projections_are_not_served() {
    let (bundle, sink) = UiBundle::live(&bundle_dir("livestale"), "/account/", CONFIG).unwrap();
    let app = router(bundle);
    let mut stream = sink.stream();
    stream
        .apply(&projection(
            5,
            &[PrincipalType::Email, PrincipalType::Username],
            6,
        ))
        .unwrap();
    for revision in [5, 4] {
        assert_eq!(
            stream.apply(&projection(revision, &[PrincipalType::Email], 0)),
            Err(SettingsRejected::Stale {
                offered: revision,
                served: 5
            })
        );
    }
    for minimum in [0, 33] {
        assert_eq!(
            stream.apply(&projection(6, &[PrincipalType::Username], minimum)),
            Err(SettingsRejected::UsernameMinimum(minimum))
        );
    }
    let config = config_json(&app).await;
    assert_eq!(config["settings"]["registrationUsernameMinLength"], 6);
    // A new stream starts from the source's current state, whatever its
    // revision: after a restore it may be lower.
    sink.stream()
        .apply(&projection(3, &[PrincipalType::Email], 0))
        .unwrap();
    let config = config_json(&app).await;
    assert_eq!(
        config["settings"]["registrationPrincipalTypes"],
        serde_json::json!(["email"])
    );
}

/// A settings change is a new entity: the old tag no longer matches, the new
/// one answers 304.
#[tokio::test]
async fn test_live_config_tag_follows_the_settings() {
    let (bundle, sink) = UiBundle::live(&bundle_dir("livetag"), "/account/", CONFIG).unwrap();
    let app = router(bundle);
    let mut stream = sink.stream();
    stream
        .apply(&projection(1, &[PrincipalType::Email], 0))
        .unwrap();
    let (_, first) = get_path(&app, Method::GET, "/account/config.json").await;
    let old = header_of(&first, header::ETAG).unwrap();
    stream
        .apply(&projection(
            2,
            &[PrincipalType::Email, PrincipalType::Username],
            6,
        ))
        .unwrap();
    let response = get_if_none_match(&app, "/account/config.json", &old).await;
    assert_eq!(response.status(), StatusCode::OK);
    let new = header_of(&response, header::ETAG).unwrap();
    assert_ne!(old, new);
    let response = get_if_none_match(&app, "/account/config.json", &new).await;
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
}

/// The installation's settings are not the deployment's to set.
#[test]
fn test_live_base_cannot_hold_settings() {
    let dir = bundle_dir("livebase");
    let config = br#"{"environment":"dev","release":"1","settings":{}}"#;
    assert!(matches!(
        UiBundle::live(&dir, "/account/", config),
        Err(BundleError::Config(_))
    ));
}

/// A scripted source: each subscription takes the next stream, whose items
/// the test sends; with none left a subscription never answers.
struct ScriptedSource {
    streams: std::collections::VecDeque<
        tokio::sync::mpsc::UnboundedReceiver<Result<PublicUiSettings, tonic::Status>>,
    >,
    subscriptions: tokio::sync::mpsc::UnboundedSender<()>,
}

struct ScriptedUpdates(
    tokio::sync::mpsc::UnboundedReceiver<Result<PublicUiSettings, tonic::Status>>,
);

impl SettingsSource for ScriptedSource {
    type Updates = ScriptedUpdates;

    async fn subscribe(&mut self) -> Result<ScriptedUpdates, tonic::Status> {
        let _ = self.subscriptions.send(());
        match self.streams.pop_front() {
            Some(stream) => Ok(ScriptedUpdates(stream)),
            None => std::future::pending().await,
        }
    }
}

impl SettingsUpdates for ScriptedUpdates {
    async fn next(&mut self) -> Result<Option<PublicUiSettings>, tonic::Status> {
        match self.0.recv().await {
            Some(item) => item.map(Some),
            None => Ok(None),
        }
    }
}

/// `follow` serves the first projection and later ones as they come; when
/// the stream fails it keeps the served one, subscribes again and serves the
/// new stream's current state.
#[tokio::test(start_paused = true)]
async fn test_follow_recovers_from_a_lost_stream() {
    let (bundle, sink) = UiBundle::live(&bundle_dir("follow"), "/account/", CONFIG).unwrap();
    let mut served = bundle.config.clone();
    let app = router(bundle);
    let (first_tx, first_rx) = tokio::sync::mpsc::unbounded_channel();
    let (second_tx, second_rx) = tokio::sync::mpsc::unbounded_channel();
    let (subscribed_tx, mut subscribed) = tokio::sync::mpsc::unbounded_channel();
    let source = ScriptedSource {
        streams: [first_rx, second_rx].into(),
        subscriptions: subscribed_tx,
    };
    tokio::spawn(follow(sink, source, Retry::default()));

    subscribed.recv().await.unwrap();
    first_tx
        .send(Ok(projection(1, &[PrincipalType::Email], 0)))
        .unwrap();
    served.wait_for(Option::is_some).await.unwrap();
    first_tx
        .send(Ok(projection(
            2,
            &[PrincipalType::Email, PrincipalType::Username],
            6,
        )))
        .unwrap();
    served.changed().await.unwrap();
    assert_eq!(
        config_json(&app).await["settings"]["registrationUsernameMinLength"],
        6
    );

    // The stream fails: the last projection stays served meanwhile.
    first_tx
        .send(Err(tonic::Status::unavailable("gone")))
        .unwrap();
    subscribed.recv().await.unwrap();
    assert_eq!(
        config_json(&app).await["settings"]["registrationUsernameMinLength"],
        6
    );
    // The new stream's current state replaces it, older revision or not.
    second_tx
        .send(Ok(projection(1, &[PrincipalType::Email], 0)))
        .unwrap();
    served.changed().await.unwrap();
    assert_eq!(
        config_json(&app).await["settings"]["registrationPrincipalTypes"],
        serde_json::json!(["email"])
    );
}

/// Regression: once the last bundle was dropped, `follow` stayed blocked on
/// an idle stream, leaking the task and its upstream subscription. It ends
/// as soon as nothing serves its configuration, idle stream or not.
#[tokio::test(start_paused = true)]
async fn test_follow_ends_with_its_last_bundle() {
    let (bundle, sink) = UiBundle::live(&bundle_dir("followend"), "/account/", CONFIG).unwrap();
    let (stream_tx, stream_rx) = tokio::sync::mpsc::unbounded_channel();
    let (subscribed_tx, mut subscribed) = tokio::sync::mpsc::unbounded_channel();
    let source = ScriptedSource {
        streams: [stream_rx].into(),
        subscriptions: subscribed_tx,
    };
    let follower = tokio::spawn(follow(sink, source, Retry::default()));
    subscribed.recv().await.unwrap();
    stream_tx
        .send(Ok(projection(1, &[PrincipalType::Email], 0)))
        .unwrap();
    // The stream stays open and idle while the bundle goes away.
    drop(bundle);
    tokio::time::timeout(std::time::Duration::from_secs(60), follower)
        .await
        .expect("follow ends once its bundle is gone")
        .unwrap();
    drop(stream_tx);
}

/// A reader that falls behind sees the latest projection only, never a
/// queue of every change.
#[tokio::test]
async fn test_slow_readers_see_the_latest_projection() {
    let (bundle, sink) = UiBundle::live(&bundle_dir("latest"), "/account/", CONFIG).unwrap();
    let mut reader = bundle.config.clone();
    let mut stream = sink.stream();
    for revision in 1..=50 {
        stream
            .apply(&projection(revision, &[PrincipalType::Email], 0))
            .unwrap();
    }
    stream
        .apply(&projection(51, &[PrincipalType::Username], 3))
        .unwrap();
    reader.changed().await.unwrap();
    let latest = reader.borrow_and_update().clone().unwrap();
    let config: serde_json::Value = serde_json::from_slice(&latest.bytes).unwrap();
    assert_eq!(config["settings"]["registrationUsernameMinLength"], 3);
    assert!(!reader.has_changed().unwrap());
}

/// Pages of the SPA, the mount path with and without its slash included,
/// get the shell, uncached so a new release is picked up at once.
#[tokio::test]
async fn test_pages_get_the_uncached_shell() {
    let app = app("pages");
    for path in [
        "/account",
        "/account/",
        "/account/login",
        "/account/login/mfa/totp",
    ] {
        let (status, response) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(
            header_of(&response, header::CACHE_CONTROL).as_deref(),
            Some("no-store")
        );
        assert!(body(response).await.contains("shell"), "{path}");
    }
}

/// Hashed assets are cached for good; the same path never changes content.
#[tokio::test]
async fn test_assets_are_immutable() {
    let (status, response) =
        get_path(&app("assets"), Method::GET, "/account/assets/app-abc123.js").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL).as_deref(),
        Some(IMMUTABLE)
    );
    assert_eq!(body(response).await, "console.log(1)");
}

/// A missing file is a 404, never the shell: a failed script load must not
/// become `200 text/html`.
#[tokio::test]
async fn test_missing_files_are_not_found() {
    let app = app("missing");
    for path in ["/account/assets/gone-123.js", "/account/robots.txt"] {
        let (status, response) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(!body(response).await.contains("shell"), "{path}");
    }
}

/// Everything under `assets/` is build output, extension or not: served
/// when it exists, 404 when it does not, never the shell.
#[tokio::test]
async fn test_extensionless_assets_are_files() {
    let dir = bundle_dir("extensionless");
    std::fs::write(dir.join("assets/runtime-config"), "data").unwrap();
    let app = router(UiBundle::new(&dir, "/account/", CONFIG).unwrap());
    let (status, response) = get_path(&app, Method::GET, "/account/assets/runtime-config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body(response).await, "data");
    let (status, response) = get_path(&app, Method::GET, "/account/assets/missing").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!body(response).await.contains("shell"));
}

/// A revalidation the file still satisfies stays a 304, not a 404.
#[tokio::test]
async fn test_conditional_requests_keep_their_status() {
    let app = app("conditional");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account/assets/app-abc123.js")
                .header(header::IF_MODIFIED_SINCE, "Fri, 31 Dec 2100 23:59:59 GMT")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NOT_MODIFIED);
}

/// A symlink in the bundle never leads outside it.
#[cfg(unix)]
#[tokio::test]
async fn test_symlinks_out_of_the_bundle_are_refused() {
    let dir = bundle_dir("symlink");
    let outside = std::env::temp_dir().join(format!("sid-ui-host-secret-{}", std::process::id()));
    std::fs::write(&outside, "secret").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("assets/leak.txt")).unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("leak.txt")).unwrap();
    let app = router(UiBundle::new(&dir, "/account/", CONFIG).unwrap());
    for path in ["/account/assets/leak.txt", "/account/leak.txt"] {
        let (status, response) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert!(!body(response).await.contains("secret"), "{path}");
    }
}

/// A mount path is a literal path, never route syntax that would capture
/// other paths of the host.
#[test]
fn test_route_syntax_in_mounts_is_refused() {
    let dir = bundle_dir("mountsyntax");
    for mount in ["/{tenant}/", "/*all/", "/a//b/", "/a b/", "/:id/"] {
        assert!(
            matches!(
                UiBundle::new(&dir, mount, CONFIG),
                Err(BundleError::Mount(_))
            ),
            "{mount}"
        );
    }
    assert!(UiBundle::new(&dir, "/account/v-2_x.y~/", CONFIG).is_ok());
}

/// The standalone service refuses a mount that would collide with its own
/// health route instead of panicking while building routes.
#[test]
fn test_standalone_refuses_the_health_mount() {
    let dir = bundle_dir("healthmount");
    let bundle = UiBundle::new(&dir, "/health/", CONFIG).unwrap();
    assert!(matches!(standalone(bundle), Err(BundleError::Mount(_))));
    assert!(standalone(UiBundle::new(&dir, "/account/", CONFIG).unwrap()).is_ok());
}

/// A shell that leads outside the bundle is refused at start, as every
/// page would later fail.
#[cfg(unix)]
#[test]
fn test_shell_outside_the_bundle_is_refused() {
    let dir = std::env::temp_dir().join(format!("sid-ui-host-shelllink-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let outside = std::env::temp_dir().join(format!("sid-ui-host-outshell-{}", std::process::id()));
    std::fs::write(&outside, "shell").unwrap();
    std::os::unix::fs::symlink(&outside, dir.join("index.html")).unwrap();
    assert!(matches!(
        UiBundle::new(&dir, "/account/", CONFIG),
        Err(BundleError::NoShell(_))
    ));
}

/// Paths are classified as the browser means them: an escaped dot or letter
/// is the same file request.
#[tokio::test]
async fn test_escaped_paths_are_classified_decoded() {
    let dir = bundle_dir("escaped");
    std::fs::write(dir.join("assets/runtime-config"), "data").unwrap();
    let app = router(UiBundle::new(&dir, "/account/", CONFIG).unwrap());
    let (status, response) = get_path(&app, Method::GET, "/account/%61ssets/runtime-config").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body(response).await, "data");
    let (status, _) = get_path(&app, Method::GET, "/account/robots%2Etxt").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = get_path(&app, Method::GET, "/account/config%2Ejson").await;
    assert_eq!(status, StatusCode::OK);
}

/// A refused method says which ones the UI answers (RFC 9110 §15.5.6).
#[tokio::test]
async fn test_method_not_allowed_names_the_allowed() {
    let (status, response) = get_path(&app("allow"), Method::DELETE, "/account/login").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(
        header_of(&response, header::ALLOW).as_deref(),
        Some("GET, HEAD")
    );
}

/// A directory is not a file: it is a 404, never a redirect that would leave
/// the mount.
#[tokio::test]
async fn test_directories_are_not_found() {
    let dir = bundle_dir("directory");
    std::fs::create_dir_all(dir.join("assets/icons")).unwrap();
    let app = router(UiBundle::new(&dir, "/account/", CONFIG).unwrap());
    let (status, response) = get_path(&app, Method::GET, "/account/assets/icons").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(header_of(&response, header::LOCATION).is_none());
}

/// Only a successful asset or its revalidation is cached for good; a
/// request-specific error is not, and no 404 is cached at all.
#[tokio::test]
async fn test_errors_are_never_cached() {
    let app = app("errorcache");
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/account/assets/app-abc123.js")
                .header(header::RANGE, "bytes=1000-2000")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
    for path in ["/account/favicon-missing.ico", "/account/assets/gone-1.js"] {
        let (status, response) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(
            header_of(&response, header::CACHE_CONTROL).as_deref(),
            Some("no-store"),
            "{path}"
        );
    }
}

/// A dot segment in a mount would be normalized away by the browser, so the
/// UI would be unreachable; it is refused.
#[test]
fn test_dot_segments_in_mounts_are_refused() {
    let dir = bundle_dir("dotmount");
    for mount in ["/./", "/../", "/account/../ui/", "/a/./b/"] {
        assert!(
            matches!(
                UiBundle::new(&dir, mount, CONFIG),
                Err(BundleError::Mount(_))
            ),
            "{mount}"
        );
    }
    assert!(UiBundle::new(&dir, "/v1.2/", CONFIG).is_ok());
}

/// A HEAD answer has the GET headers and no body, the configuration included.
#[tokio::test]
async fn test_head_has_no_body() {
    let app = app("headbody");
    for path in [
        "/account/config.json",
        "/account/login",
        "/account/assets/app-abc123.js",
    ] {
        let (status, response) = get_path(&app, Method::HEAD, path).await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert_eq!(body(response).await, "", "{path}");
    }
}

/// Dot segments (also behind encoded separators) and hidden files are never
/// served: neither an alias of the shell under the asset cache policy nor
/// a `.env` left in the bundle directory.
#[tokio::test]
async fn test_dot_and_hidden_segments_are_not_found() {
    let dir = bundle_dir("hidden");
    std::fs::write(dir.join(".env"), "SECRET=1").unwrap();
    std::fs::create_dir_all(dir.join(".git")).unwrap();
    std::fs::write(dir.join(".git/config"), "x").unwrap();
    let app = router(UiBundle::new(&dir, "/account/", CONFIG).unwrap());
    for path in [
        "/account/.env",
        "/account/.git/config",
        "/account/assets%2F..%2Findex.html",
        "/account/assets/.%2Fapp-abc123.js",
    ] {
        let (status, response) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
        let text = body(response).await;
        assert!(
            !text.contains("SECRET") && !text.contains("shell"),
            "{path}"
        );
    }
}

/// A file at the bundle root is served, uncached.
#[tokio::test]
async fn test_root_files_are_served() {
    let (status, response) = get_path(&app("root"), Method::GET, "/account/favicon.ico").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        header_of(&response, header::CACHE_CONTROL).as_deref(),
        Some("no-store")
    );
}

/// Nothing outside the bundle directory is reachable through the mount.
#[tokio::test]
async fn test_traversal_is_refused() {
    let app = app("traversal");
    for path in [
        "/account/../Cargo.toml",
        "/account/assets/../../etc/passwd.txt",
        "/account/%2e%2e/secret.txt",
    ] {
        let (status, _) = get_path(&app, Method::GET, path).await;
        assert_ne!(status, StatusCode::OK, "{path}");
    }
}

/// Paths outside the mount are not the UI's: protocol endpoints, callbacks
/// and APIs on the same origin are left to their owners.
#[tokio::test]
async fn test_other_paths_are_not_served() {
    let app = app("outside");
    for path in [
        "/",
        "/auth/callback",
        "/api/v1/x",
        "/i/abc/oauth2/authorize",
        "/accounts",
    ] {
        let (status, _) = get_path(&app, Method::GET, path).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// The UI is read-only.
#[tokio::test]
async fn test_only_reads_are_allowed() {
    let (status, _) = get_path(&app("methods"), Method::POST, "/account/login").await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    let (status, _) = get_path(&app("head"), Method::HEAD, "/account/login").await;
    assert_eq!(status, StatusCode::OK);
}

/// Every response isolates the page, as the threaded password client needs.
#[tokio::test]
async fn test_responses_are_cross_origin_isolated() {
    let (_, response) = get_path(&app("isolation"), Method::GET, "/account/login").await;
    assert_eq!(
        header_of(&response, "cross-origin-opener-policy".parse().unwrap()).as_deref(),
        Some("same-origin")
    );
    assert_eq!(
        header_of(&response, "cross-origin-embedder-policy".parse().unwrap()).as_deref(),
        Some("credentialless")
    );
}

/// A bundle or configuration that cannot be served is refused at start.
#[test]
fn test_unusable_bundles_are_refused() {
    let dir = bundle_dir("refused");
    assert!(matches!(
        UiBundle::new(&dir, "account/", CONFIG),
        Err(BundleError::Mount(_))
    ));
    assert!(matches!(
        UiBundle::new(&dir, "/account", CONFIG),
        Err(BundleError::Mount(_))
    ));
    let empty = std::env::temp_dir().join(format!("sid-ui-host-empty-{}", std::process::id()));
    std::fs::create_dir_all(&empty).unwrap();
    assert!(matches!(
        UiBundle::new(&empty, "/account/", CONFIG),
        Err(BundleError::NoShell(_))
    ));
    for config in [
        &b"[]"[..],
        b"{",
        br#"{"release":"1"}"#,
        br#"{"environment":"","release":"1"}"#,
    ] {
        assert!(
            matches!(
                UiBundle::new(&dir, "/account/", config),
                Err(BundleError::Config(_))
            ),
            "{}",
            String::from_utf8_lossy(config)
        );
    }
}

/// Embedded in a host application's router, the UI serves its mount and the
/// host keeps every other route, on the one listener.
#[tokio::test]
async fn test_embedded_beside_host_routes() {
    let host = Router::new()
        .route("/api/v1/ping", axum::routing::get(|| async { "pong" }))
        .merge(app("embedded"));
    let (status, response) = get_path(&host, Method::GET, "/api/v1/ping").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body(response).await, "pong");
    let (status, response) = get_path(&host, Method::GET, "/account/login").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body(response).await.contains("shell"));
}

/// A bundle mounted at the root serves its pages at `/`.
#[tokio::test]
async fn test_root_mount() {
    let app = router(UiBundle::new(&bundle_dir("rootmount"), "/", CONFIG).unwrap());
    let (status, _) = get_path(&app, Method::GET, "/").await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = get_path(&app, Method::GET, "/config.json").await;
    assert_eq!(status, StatusCode::OK);
}
