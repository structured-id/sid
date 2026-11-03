// SPDX-License-Identifier: AGPL-3.0-only
//! Who may call the template API. Every call carries an access token for the
//! installation's account API resource, the resource the administration UI
//! signs in to; this service is one more process serving it. The shared
//! receiver verifies the token and asks the issuer whether its subject may
//! perform the action the method performs, which also establishes that the
//! token, its session and its subject are current. Methods are mapped one by
//! one: a method without an action here is never served.

use std::sync::Arc;

use sid_auth::receiver::{Action, Actions, Guarded, Receiver};

/// Reading templates and rendering previews.
pub const TEMPLATE_READ: &str = "notify.template.read";
/// Customizing a template or restoring its default.
pub const TEMPLATE_CHANGE: &str = "notify.template.change";
/// Sending a template to a test recipient.
pub const TEMPLATE_TEST: &str = "notify.template.test";

/// The action a call to `path` (`/package.Service/Method`) performs.
pub fn action(path: &str) -> Option<Action> {
    let method = path.strip_prefix("/sid.v1.admin.NotificationTemplateService/")?;
    Some(Action::OnResource(match method {
        "ListTemplates" | "GetTemplate" | "PreviewTemplate" => TEMPLATE_READ,
        "UpdateTemplate" | "ResetTemplate" => TEMPLATE_CHANGE,
        "SendTestNotification" => TEMPLATE_TEST,
        _ => return None,
    }))
}

/// `service` served behind `receiver`: only admitted calls reach it.
pub fn guarded<S>(service: S, receiver: &Arc<Receiver>) -> Guarded<S> {
    let actions: Actions = Arc::new(action);
    Guarded::new(service, receiver.clone(), actions)
}
