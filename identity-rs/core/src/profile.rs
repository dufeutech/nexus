//! The canonical Profile — the single definition shared by the sidecar (reads),
//! the sync-worker (writes from change events), and the reconciler (writes from
//! the authoritative list). Field identifiers are normalized lower `snake_case`
//! (RFC §3.8); mapping from the provider's casing happens at the boundary.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct Profile {
    #[serde(default)]
    pub sub: String,
    #[serde(default)]
    pub org_id: Option<String>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub preferred_language: Option<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub entitlements: Vec<String>,
    #[serde(default)]
    pub is_suspended: bool,
    /// Monotonic per-key version derived from the authoritative change marker
    /// (RFC §3.3). A write with an older version MUST NOT overwrite a newer one.
    #[serde(default)]
    pub version: i64,
    #[serde(default)]
    pub updated_at: Option<String>,
}
