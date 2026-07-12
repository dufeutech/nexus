//! Shared application state + the resolver core: the `AppState` handle, its
//! profile/plan/platform/signer resolution, the RED metrics, the trusted header
//! consts, and the fail-closed predicate. The surfaces (`serve`, `api`) and the
//! bootstrap wiring build on these.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::sync::LazyLock;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use moka::future::Cache;
use tokio::sync::watch;
use tracing::warn;
use opentelemetry::metrics::{Counter, Gauge, Histogram};
use opentelemetry::global;

use identity_core::store::ProfileStore;
use identity_core::{
    ApiKeyCandidate, ApiKeyReader, PlatformScope, PolicyDecisionPoint, Profile, SecretHasher,
};

use crate::signer;
use crate::token_cache::ContractTokenCache;

// --------------------------------------------------------------------------- //
// Metrics (first-party-telemetry): the RED baseline + operational gauges, emitted
// through the OTel meter (push path via identity_core::telemetry). Counter names
// DROP the Prometheus `_total` suffix — Prometheus's OTLP receiver re-appends it, so
// the stored series keep their names (sidecar_ext_proc_requests_total, …). The
// duration histogram carries the same explicit buckets as before.
// --------------------------------------------------------------------------- //
pub(crate) struct Metrics {
    pub(crate) ext_proc_duration: Histogram<f64>,
    pub(crate) ext_proc_requests: Counter<u64>,
    pub(crate) cache_hits: Counter<u64>,
    pub(crate) cache_misses: Counter<u64>,
    /// hot-path-rps-optimization: reuse of a cached signed contract (a skipped ES256
    /// sign) vs a mint (cache miss or expiry-safe re-mint). The hit-rate is the RPS win.
    pub(crate) contract_cache_hits: Counter<u64>,
    pub(crate) contract_cache_mints: Counter<u64>,
    /// apikey-resolve-cache: the opt-in working-set cache on the api-key resolve path.
    /// `hits`/`misses` are the effectiveness signal (a hit is a skipped live SELECT);
    /// `evictions` counts change-feed-driven targeted invalidations (revoke/rotate).
    pub(crate) apikey_resolve_cache_hits: Counter<u64>,
    pub(crate) apikey_resolve_cache_misses: Counter<u64>,
    pub(crate) apikey_resolve_cache_evictions: Counter<u64>,
    pub(crate) kv_updates: Counter<u64>,
    pub(crate) cache_entries: Gauge<u64>,
    pub(crate) ready: Gauge<u64>,
    pub(crate) kv_last_apply: Gauge<f64>,
    pub(crate) time_to_warm: Gauge<f64>,
}

pub(crate) static METRICS: LazyLock<Metrics> = LazyLock::new(|| {
    let meter = global::meter("identity-sidecar");
    Metrics {
        ext_proc_duration: meter
            .f64_histogram("sidecar_ext_proc_duration_seconds")
            .with_unit("s")
            .with_boundaries(vec![
                0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05,
                0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ])
            .build(),
        ext_proc_requests: meter.u64_counter("sidecar_ext_proc_requests").build(),
        cache_hits: meter.u64_counter("sidecar_cache_hits").build(),
        cache_misses: meter.u64_counter("sidecar_cache_misses").build(),
        contract_cache_hits: meter.u64_counter("sidecar_contract_cache_hits").build(),
        contract_cache_mints: meter.u64_counter("sidecar_contract_cache_mints").build(),
        apikey_resolve_cache_hits: meter.u64_counter("sidecar_apikey_resolve_cache_hits").build(),
        apikey_resolve_cache_misses: meter.u64_counter("sidecar_apikey_resolve_cache_misses").build(),
        apikey_resolve_cache_evictions: meter
            .u64_counter("sidecar_apikey_resolve_cache_evictions")
            .build(),
        kv_updates: meter.u64_counter("sidecar_kv_updates").build(),
        cache_entries: meter.u64_gauge("sidecar_cache_entries").build(),
        ready: meter.u64_gauge("sidecar_ready").build(),
        kv_last_apply: meter
            .f64_gauge("sidecar_kv_last_apply_timestamp_seconds")
            .build(),
        time_to_warm: meter.f64_gauge("sidecar_time_to_warm_seconds").build(),
    }
});

pub(crate) const JWT_NS: &str = "envoy.filters.http.jwt_authn";
pub(crate) const PAYLOAD_KEY: &str = "verified";
/// The metadata key the SECOND `jwt_authn` provider (the core-service infra-trust
/// token) writes its verified payload under, within the same `jwt_authn` namespace
/// (`payload_in_metadata: verified_service` in `edge/envoy.yaml`). Its presence — and a
/// `sub` inside it — is what the authenticator chain reads to produce a `Service`
/// principal (normalized-principal). Kept distinct from the human `verified` key so the
/// two providers never collide.
pub(crate) const SVC_PAYLOAD_KEY: &str = "verified_service";

/// Version of the edge→backend identity-header contract this sidecar emits. Since
/// `identity-contract-signing`, `x-identity-contract` is a *signed token* and this
/// value rides inside it as the `ctr` claim (it is no longer the raw header value). It
/// is the single coordination gate for the whole `x-workspace-*`/`x-user-*` family:
/// any drift in that family's shape (a rename, a removed/added field, a changed
/// meaning) is a version bump, so a partially-deployed contract change fails closed
/// instead of feeding the backend headers it silently misreads. A well-formed token
/// also carries the authoritative acting scope (`workspace_id`/`member_type`/`role`),
/// so the acting-scope guarantee is PART of this version. SHARED CONTRACT: the value is
/// coordinated cross-repo with the consuming backend/box — bump both sides together.
pub(crate) const IDENTITY_CONTRACT_VERSION: &str = "v1";

/// Per-route requirement signals (N4 phase 2), emitted by the tenant-router from
/// the tenant's resolved auth policy and C3-stripped from client input — trusted
/// by the time they reach this filter. On the wire, absence IS the
/// no-requirement state; this filter enforces them (403) and strips them before
/// the backend (policy detail never leaves the edge).
pub(crate) const HDR_REQUIRES_ROLE: &str = "x-auth-requires-role";
pub(crate) const HDR_REQUIRES_ENTITLEMENT: &str = "x-auth-requires-entitlement";
pub(crate) const HDR_MIN_AAL: &str = "x-auth-min-aal";
/// identity-existence-hiding: the per-route gate signals the sidecar reads to
/// decide the membership-404. `x-auth-required` (always emitted by the
/// tenant-router) marks an *enriched* (private) route; `x-auth-account-scoped`
/// (emitted only when set) marks a protected route as account-scoped — reachable
/// without a workspace membership. Both are trusted-emitted and C3-stripped from
/// client input, so a client can neither forge nor suppress them; absence of the
/// account-scoped signal is the fail-closed (workspace-scoped, gated) state.
pub(crate) const HDR_AUTH_REQUIRED: &str = "x-auth-required";
pub(crate) const HDR_ACCOUNT_SCOPED: &str = "x-auth-account-scoped";

/// Method→assurance-level ordering (N4 phase 2): the single owner of "how strong
/// is this authentication method". Data-driven via `SIDECAR_AAL_LEVELS`
/// (`method=level[,method=level…]`) so richer methods (MFA/passkey) slot in
/// without a rebuild once `x-auth-method` distinguishes them; a method missing
/// from the map fails any min-AAL requirement (closed), never defaults up.
pub(crate) const DEFAULT_AAL_LEVELS: &str = "none=0,bearer=1";

pub(crate) fn parse_aal_levels(spec: &str) -> HashMap<String, u8> {
    spec.split(',')
        .filter_map(|pair| {
            let (method, level) = pair.split_once('=')?;
            Some((method.trim().to_ascii_lowercase(), level.trim().parse().ok()?))
        })
        .collect()
}

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Wall-clock seconds since the Unix epoch — the `iat`/`exp` basis for a minted
/// contract token (identity-contract-signing).
pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) cache: Cache<String, Arc<Profile>>,
    pub(crate) store: Arc<dyn ProfileStore>,
    pub(crate) ready: Arc<AtomicBool>,
    pub(crate) last_apply_ms: Arc<AtomicU64>, // epoch millis of the last applied change
    pub(crate) warm_ms: Arc<AtomicU64>,       // time-to-warm in ms (0 until ready)
    pub(crate) start: Instant,
    /// Security/availability trade for the case where an authenticated request's
    /// profile CANNOT be read (store down / never connected). `false` (default)
    /// fails CLOSED — block with 503 rather than serve a request whose
    /// revocation-sensitive state (`is_suspended`) is unknown, which would let a
    /// suspended user back in during a Postgres outage. `true` restores the prior
    /// availability-first behavior (enrich without a profile). A genuinely absent
    /// profile (no row) is NOT this case and never fails closed.
    pub(crate) fail_open: bool,
    /// The method→AAL ordering the min-AAL requirement compares against
    /// (`SIDECAR_AAL_LEVELS`, default [`DEFAULT_AAL_LEVELS`]).
    pub(crate) aal_levels: Arc<HashMap<String, u8>>,
    /// The ES256 signer for the `x-identity-contract` token (identity-contract-signing).
    /// A `watch` receiver so the ACTIVE signer is swap-able under automated rotation
    /// (automate-signing-key-rotation): the rotation manager republishes it on each
    /// cut-over and the hot path reads the current one with a cheap `Arc` clone. In
    /// break-glass mode it wraps the static `SIGNING_KEY_PATH` PEM signer (never changes).
    /// `None` when signing is not configured — then no token is minted and any client copy
    /// is stripped, so a verifying box fails closed.
    pub(crate) signer: Option<watch::Receiver<Arc<signer::Signer>>>,
    /// hot-path-rps-optimization: the in-process reuse cache for the signed
    /// `x-identity-contract`. A hit skips the ES256 signature entirely. `None` disables
    /// reuse (sign-per-request) — set when signing is off or `CONTRACT_CACHE_ENABLED=false`.
    /// Rotation-safe by construction (the active `kid` is part of its key), so it needs no
    /// coordination with the signer `watch` swap. See [`crate::token_cache`].
    pub(crate) contract_cache: Option<ContractTokenCache>,
    /// The RESIDENT active platform-service registry (`service_id` → its least-privilege
    /// [`PlatformScope`]), refreshed LIVE off the `platform.services` change feed
    /// (normalized-principal ADR-7). `None` when platform-service auth is not configured
    /// (`PLATFORM_PG_RO_URL` unset) — then no service ever resolves (human path only). A
    /// present-but-empty map means the registry is loaded with no active services (or is
    /// cold-starting): every service then resolves to no authority and fails closed.
    pub(crate) platform: Option<watch::Receiver<Arc<HashMap<String, PlatformScope>>>>,
    /// The RESIDENT `workspace_id` → plan snapshot (`workspace-plan-tier`), refreshed LIVE
    /// off the routing plane's workspace-invalidation change feed. `None` when plan
    /// projection is not configured (`ROUTING_PG_RO_URL` unset) — then no plan ever
    /// resolves and `x-workspace-plan`/the `plan` claim are simply omitted (fail-soft, NOT
    /// a 503 — distinct from membership's fail-closed). A workspace absent from the map
    /// resolves to no plan, which a box treats as not-provisioned.
    pub(crate) plans: Option<watch::Receiver<Arc<HashMap<String, String>>>>,
    /// API-key authentication (`customer-api-keys`): the live key reader + secret hasher.
    /// `None` when not configured (`APIKEY_PG_RO_URL`/`APIKEY_HMAC_PEPPER` unset) — then
    /// no `x-api-key` ever resolves (human/service paths only, fail closed).
    pub(crate) api_keys: Option<ApiKeyAuth>,
    /// The L2 authorization policy decision point (adopt-cedar-policy-gate). The gated-
    /// route 403 step (`decide_route_requirements`) asks this port instead of comparing
    /// headers by hand — a Cedar adapter in production, or [`DenyAllPdp`] when the policy
    /// set failed to load (gated routes then fail closed). An `Arc<dyn …>` so the engine
    /// is a reversible adapter swap and cheap to clone per request.
    pub(crate) pdp: Arc<dyn PolicyDecisionPoint>,
}

/// The api-key authenticator's dependencies (`customer-api-keys`): the live store reader
/// and the keyed hasher. Verifying a presented secret is: hash it, then resolve the hash
/// to a live (`active`, unexpired) key — a single indexed lookup, fail-closed on miss.
#[derive(Clone)]
pub(crate) struct ApiKeyAuth {
    pub(crate) reader: Arc<dyn ApiKeyReader>,
    pub(crate) hasher: Arc<dyn SecretHasher>,
}

impl ApiKeyAuth {
    /// Resolve a presented `x-api-key` secret to its live key candidate, or `None` (fail
    /// closed) when it hashes to no active, unexpired key — or when the lookup itself
    /// fails (a store blip is "cannot decide", never an admit).
    pub(crate) async fn resolve(&self, presented_secret: &str) -> Option<ApiKeyCandidate> {
        let hash = self.hasher.hash(presented_secret);
        match self.reader.lookup(&hash).await {
            Ok(candidate) => candidate,
            Err(e) => {
                warn!(error = %e, "api-key lookup failed -> fail closed");
                None
            }
        }
    }
}

/// The outcome of resolving a subject's profile — distinguishes "no row" (a
/// legitimate authenticated-but-unprofiled user) from "could not read" (store
/// unavailable), which the fail-closed rule depends on.
pub(crate) enum Resolved {
    Found(Arc<Profile>),
    Absent,
    Unavailable,
}

impl AppState {
    /// Cache-first resolve; on miss/expiry, a single coalesced store read (C5).
    /// At 1B scale this miss-load is a normal steady-state path, not a rare
    /// fallback — the cache holds only the hot working set.
    pub(crate) async fn resolve(&self, sub: &str) -> Resolved {
        if let Some(p) = self.cache.get(sub).await {
            METRICS.cache_hits.add(1, &[]);
            return Resolved::Found(p);
        }
        METRICS.cache_misses.add(1, &[]);
        let store = self.store.clone();
        let key = sub.to_owned();
        // try_get_with does not cache the error, so a transient store failure is
        // retried on the next request rather than negatively cached. The
        // "not_found" sentinel is the only non-error "absent" signal.
        match self
            .cache
            .try_get_with(key.clone(), async move {
                match store.get(&key).await {
                    Ok(Some(p)) => Ok(Arc::new(p)),
                    Ok(None) => Err("not_found".to_owned()),
                    Err(e) => Err(e.to_string()),
                }
            })
            .await
        {
            Ok(p) => Resolved::Found(p),
            Err(e) if e.as_str() == "not_found" => Resolved::Absent,
            Err(e) => {
                warn!(error = %e, "profile store read failed");
                Resolved::Unavailable
            }
        }
    }

    /// Resolve a core service's platform authority from the resident registry (task
    /// 2.4). `Some(scope)` iff the service is present in the current ACTIVE set;
    /// `None` for an absent/inactive service OR when platform-service auth is not
    /// configured — either way the caller fails closed (no authority → no contract →
    /// the box rejects). Revocation propagates within seconds because the registry map
    /// is refreshed off the `platform.services` change feed.
    pub(crate) fn resolve_platform_scope(&self, service_id: &str) -> Option<PlatformScope> {
        self.platform
            .as_ref()
            .and_then(|rx| rx.borrow().get(service_id).cloned())
    }

    /// Resolve the acting workspace's plan tier from the resident snapshot
    /// (`workspace-plan-tier` task 3.2). `Some(plan)` iff the workspace is present in the
    /// current set; `None` for an unknown workspace OR when plan projection is not
    /// configured — either way the caller omits the plan (fail-soft, NOT a 503): a box
    /// treats an absent plan as not-provisioned. A change propagates within seconds because
    /// the map is refreshed off the routing workspace change feed. Mirrors
    /// [`Self::resolve_platform_scope`].
    pub(crate) fn resolve_plan(&self, workspace_id: &str) -> Option<String> {
        self.plans
            .as_ref()
            .and_then(|rx| rx.borrow().get(workspace_id).cloned())
    }

    /// The CURRENT active contract signer (automate-signing-key-rotation). Reads the
    /// swap-able `watch` value with a cheap `Arc` clone so no borrow guard is held across
    /// the mint — a rotation cut-over is picked up on the next request with no restart.
    /// `None` when signing is not configured.
    pub(crate) fn current_signer(&self) -> Option<Arc<signer::Signer>> {
        self.signer.as_ref().map(|rx| rx.borrow().clone())
    }
}

/// The fail-closed rule, isolated so it is unit-testable without a store: an
/// authenticated request whose profile is store-UNAVAILABLE must be blocked
/// unless fail-open is configured. Anonymous requests, found profiles, and
/// genuinely absent profiles never fail closed.
pub(crate) const fn must_fail_closed(authenticated: bool, unavailable: bool, fail_open: bool) -> bool {
    authenticated && unavailable && !fail_open
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use identity_core::store::BoxError;
    use store_postgres::HmacSecretHasher;

    #[test]
    fn fail_closed_only_for_authenticated_unavailable_when_not_open() {
        // The one and only case that blocks: authenticated + store unavailable +
        // fail-open disabled.
        assert!(must_fail_closed(true, true, false));
        // Fail-open configured → never block.
        assert!(!must_fail_closed(true, true, true));
        // Anonymous never blocks (it never touches the store).
        assert!(!must_fail_closed(false, true, false));
        // Store readable (found/absent) never blocks.
        assert!(!must_fail_closed(true, false, false));
    }

    #[test]
    fn resolve_platform_scope_reads_the_resident_registry() {
        // Task 2.4: a service present in the ACTIVE set resolves to its scope; an
        // absent one resolves to None (fail closed); with NO registry configured,
        // nothing resolves (the human-only deployment).
        let mut map = HashMap::new();
        map.insert(
            "svc-1".to_owned(),
            PlatformScope::new(vec!["events:write".to_owned()]),
        );
        let (_tx, rx) = watch::channel(Arc::new(map));
        let state = state_with_platform(Some(rx));
        assert!(state.resolve_platform_scope("svc-1").expect("active").allows("events:write"));
        assert!(state.resolve_platform_scope("svc-absent").is_none(), "unregistered = no authority");
        assert!(
            state_with_platform(None).resolve_platform_scope("svc-1").is_none(),
            "no registry configured -> no service resolves",
        );
    }

    #[test]
    fn resolve_plan_reads_the_resident_snapshot() {
        // Task 3.2 / 4.1: a workspace present in the resident set resolves to its plan; an
        // absent one resolves to None (omitted downstream); with NO projection configured,
        // nothing resolves. A live snapshot swap is reflected on the next read (a
        // downgrade/upgrade takes effect without a token refresh).
        let mut map = HashMap::new();
        map.insert("ws-pro".to_owned(), "pro".to_owned());
        let (tx, rx) = watch::channel(Arc::new(map));
        let state = state_with_plans(Some(rx));
        assert_eq!(state.resolve_plan("ws-pro").as_deref(), Some("pro"));
        assert!(state.resolve_plan("ws-unknown").is_none(), "unknown workspace -> no plan");
        assert!(
            state_with_plans(None).resolve_plan("ws-pro").is_none(),
            "no projection configured -> no plan resolves",
        );
        // A downgrade lands on the next read — no token refresh, mirroring suspension.
        tx.send(Arc::new(HashMap::from([("ws-pro".to_owned(), "free".to_owned())]))).unwrap();
        assert_eq!(state.resolve_plan("ws-pro").as_deref(), Some("free"), "downgrade is prompt");
    }

    #[tokio::test]
    async fn api_key_auth_resolves_live_and_fails_closed() {
        // Task 4.3 at the resolve layer: ApiKeyAuth hashes the presented secret and
        // resolves it through the reader. A live key -> Some(candidate); a revoked/
        // expired/unknown key (reader yields None) -> None; a reader error -> None (fail
        // closed, never an admit).
        use identity_core::{ApiKeyCandidate, ApiKeyScope};

        struct FakeReader {
            // The one hash the "live" key is stored under.
            live_hash: Option<String>,
            err: bool,
        }
        #[tonic::async_trait]
        impl ApiKeyReader for FakeReader {
            async fn lookup(&self, key_hash: &str) -> Result<Option<ApiKeyCandidate>, BoxError> {
                if self.err {
                    return Err("store blip".into());
                }
                Ok(self.live_hash.as_deref().filter(|h| *h == key_hash).map(|_| ApiKeyCandidate {
                    key_id: "pak_1".to_owned(),
                    creator_sub: "u-creator".to_owned(),
                    scope: ApiKeyScope::new(vec!["ws-1".to_owned()]),
                    expires_at: None,
                }))
            }
        }

        let hasher: Arc<dyn SecretHasher> = Arc::new(HmacSecretHasher::new(b"pepper".to_vec()));
        let live_hash = hasher.hash("nexus_pat_good");

        let live = ApiKeyAuth {
            reader: Arc::new(FakeReader { live_hash: Some(live_hash), err: false }),
            hasher: hasher.clone(),
        };
        assert_eq!(
            live.resolve("nexus_pat_good").await.map(|c| c.key_id),
            Some("pak_1".to_owned()),
            "a live key must resolve to its candidate",
        );
        assert!(live.resolve("nexus_pat_wrong").await.is_none(), "a non-matching secret must fail closed");

        // A revoked/expired/unknown key: the reader surfaces no live row.
        let revoked = ApiKeyAuth {
            reader: Arc::new(FakeReader { live_hash: None, err: false }),
            hasher: hasher.clone(),
        };
        assert!(revoked.resolve("nexus_pat_good").await.is_none(), "no live row -> fail closed");

        // A store error is "cannot decide", never an admit.
        let broken = ApiKeyAuth {
            reader: Arc::new(FakeReader { live_hash: None, err: true }),
            hasher,
        };
        assert!(broken.resolve("nexus_pat_good").await.is_none(), "reader error -> fail closed");
    }

    #[test]
    fn aal_levels_parse_with_default_and_override() {
        let d = levels();
        assert_eq!(d.get("none").copied(), Some(0));
        assert_eq!(d.get("bearer").copied(), Some(1));
        // An override adds methods and skips malformed pairs instead of failing.
        let custom = parse_aal_levels("none=0, Bearer=1, mfa=2, bogus, empty=");
        assert_eq!(custom.get("bearer").copied(), Some(1));
        assert_eq!(custom.get("mfa").copied(), Some(2));
        assert_eq!(custom.len(), 3);
    }

}
