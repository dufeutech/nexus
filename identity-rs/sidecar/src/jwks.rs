//! Dedicated public JWKS listener (identity-contract-signing). Publishes the PUBLIC
//! verification keys for the signed `x-identity-contract` token — so a box can fetch
//! and cache them and verify a token's signature/`iss`/`aud`/`exp` itself.
//!
//! Deliberately a SEPARATE surface from the `:9200` profile API: that server exposes
//! `/profile/{sub}` (sensitive) and must stay internal, whereas the JWKS is public and
//! box-reachable.
//!
//! Since automate-signing-key-rotation the served document is **swap-able**: the
//! rotation manager ([`crate::rotation`]) regenerates it from the key provider's public
//! keys on every rotation and publishes it over a `watch` channel, so a two-key overlap
//! window appears automatically as a two-entry `keys` array with NO hand-sync step. In
//! break-glass mode the operator-supplied `JWKS_FILE` is wrapped in a never-changing
//! `watch` and served through the same path. Each request reads the CURRENT document, so
//! a rotation is visible to boxes without a restart.

use std::sync::Arc;

use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use tokio::sync::watch;

/// The well-known path boxes fetch the key set from (`iss` + this path).
pub(crate) const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Build the JWKS router over a swap-able document. `document` is a `watch` receiver the
/// rotation manager republishes on every rotation (or a never-changing channel wrapping
/// the break-glass `JWKS_FILE`); each request serves the CURRENT value with a JSON
/// content type, so the published overlap set tracks rotation with no restart.
pub(crate) fn router(document: watch::Receiver<Arc<String>>) -> Router {
    Router::new().route(
        JWKS_PATH,
        get(move || {
            let body = document.borrow().clone();
            async move { ([(CONTENT_TYPE, "application/json")], body.as_str().to_owned()).into_response() }
        }),
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        reason = "tests legitimately unwrap on fixtures known to be valid"
    )]
    use super::*;
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    #[tokio::test]
    async fn serves_the_supplied_jwks_verbatim_as_json() {
        let doc = Arc::new(r#"{"keys":[{"kid":"k1"}]}"#.to_owned());
        let (_tx, rx) = watch::channel(Arc::clone(&doc));
        let app = router(rx);
        let resp = app
            .oneshot(Request::builder().uri(JWKS_PATH).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json",
            "JWKS must be served as JSON",
        );
        let bytes = to_bytes(resp.into_body(), 64 * 1024).await.unwrap();
        assert_eq!(bytes.as_ref(), doc.as_bytes(), "document must be served verbatim");
    }
}
