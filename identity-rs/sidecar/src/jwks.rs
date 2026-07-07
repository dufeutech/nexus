//! Dedicated public JWKS listener (identity-contract-signing). Publishes the
//! operator-supplied JWKS document — the PUBLIC verification keys for the signed
//! `x-identity-contract` token — so a box can fetch and cache them and verify a
//! token's signature/`iss`/`aud`/`exp` itself.
//!
//! Deliberately a SEPARATE surface from the `:9200` profile API: that server exposes
//! `/profile/{sub}` (sensitive) and must stay internal, whereas the JWKS is public and
//! box-reachable. The document is operator-supplied and served **verbatim** — the
//! sidecar never derives public keys from the private signing key, so no EC-parsing
//! dependency is pulled in. Rotation = update the mounted JWKS file (publish the new
//! `kid` before the signer starts using it; keep the retired key until its tokens
//! expire).

use std::sync::Arc;

use axum::http::header::CONTENT_TYPE;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;

/// The well-known path boxes fetch the key set from (`iss` + this path).
pub(crate) const JWKS_PATH: &str = "/.well-known/jwks.json";

/// Build the JWKS router. `document` is the operator-supplied JSON, loaded once at
/// startup and served verbatim with a JSON content type. Supporting multiple keys
/// (rotation overlap) is inherent — whatever the operator publishes in the document is
/// served, so a two-key overlap window is just a two-entry `keys` array.
pub(crate) fn router(document: Arc<String>) -> Router {
    Router::new().route(
        JWKS_PATH,
        get(move || {
            let body = Arc::clone(&document);
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
        let app = router(Arc::clone(&doc));
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
