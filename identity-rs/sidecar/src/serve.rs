//! The ext_proc gRPC surface ([`Sidecar`] + the `ExternalProcessor` impl) that runs
//! the authenticator chain → resolution → enrichment on the hot path, plus the
//! change-feed / platform-registry / workspace-plan watchers that keep the resident
//! state fresh, and the graceful-shutdown signal.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};
#[cfg(not(unix))]
use std::future::pending;

use futures::StreamExt;
use tokio::signal;
use tokio::sync::{mpsc, watch};
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info, info_span, warn};
use tracing::field::Empty;
use tracing::Instrument as _;
use tracing::Span;
use opentelemetry::KeyValue;

use envoy_types::pb::envoy::service::ext_proc::v3::{
    external_processor_server::ExternalProcessor, processing_request, ProcessingRequest,
    ProcessingResponse,
};

use identity_core::telemetry;
use identity_core::store::{BoxError, Change, WatchToken};
use identity_core::{Authority, PlatformScope, PrincipalKind, ScopeIntersectionResolver};
use store_postgres::{PgPlatformServiceReader, PgWorkspacePlanReader};

use crate::authz::decide_route_requirements;
use crate::enrich::{
    enrich_response, forbidden_403, hide_nonmember_as_404, not_found_404, unavailable_503,
    warming_503, Acting, Enriched, SignContext,
};
use crate::extract::{
    extract_acting_workspace, extract_api_key, extract_identity, extract_requirements,
    extract_route_pool, extract_service, trace_metadata, trusted_flag,
};
use crate::state::{
    must_fail_closed, now_ms, now_secs, AppState, Resolved, HDR_ACCOUNT_SCOPED, HDR_AUTH_REQUIRED,
    METRICS,
};

// --------------------------------------------------------------------------- //
// ext_proc service.
// --------------------------------------------------------------------------- //
#[derive(Clone)]
pub(crate) struct Sidecar {
    pub(crate) state: AppState,
}

impl Sidecar {
    async fn handle(
        &self,
        req: ProcessingRequest,
        trace_meta: &[(String, String)],
    ) -> Option<ProcessingResponse> {
        if !matches!(
            req.request,
            Some(processing_request::Request::RequestHeaders(_))
        ) {
            return None;
        }
        // Continue the edge trace: this span parents under the edge-rooted context
        // so the enrichment stage appears between the routing and backend spans (no
        // first-party hole). `enrich.result` is recorded after; the `info!`/`debug!`
        // events inside are trace-stamped for the two-way logs↔traces pivot.
        let span = info_span!("identity.enrich", enrich.result = Empty, otel.kind = "server");
        telemetry::continue_trace(&span, trace_meta.to_vec());
        self.enrich(req).instrument(span).await
    }

    async fn enrich(&self, req: ProcessingRequest) -> Option<ProcessingResponse> {
        let started = Instant::now();
        let (resp, result) = if self.state.ready.load(Ordering::Relaxed) {
            'decide: {
                // AUTHENTICATOR CHAIN (normalized-principal task 4.1): the human JWT
                // branch first; if it does not authenticate a user, consult the
                // service-token branch (the 2nd `jwt_authn` provider's metadata). A
                // human token always wins. Each branch produces the SAME normalized
                // outcome the resolution below is blind to.
                let (human_sub, human_auth) = extract_identity(&req);
                // API-KEY branch (customer-api-keys task 4.1): consulted only when no
                // human authenticated (a human JWT always wins). Resolve the presented
                // `x-api-key` to a live candidate up front so its owned key-id/creator
                // outlive the `Enriched` below; a presented-but-unresolved key (revoked/
                // expired/unknown) yields `None` and falls through to the anonymous
                // fail-closed path (task 4.3). The service branch is consulted only when
                // neither a human nor an api key is present.
                let presented_key = if human_auth { None } else { extract_api_key(&req) };
                let api_key_candidate = match (presented_key.as_deref(), self.state.api_keys.as_ref())
                {
                    (Some(secret), Some(auth)) => auth.resolve(secret).await,
                    _ => None,
                };
                let service_id = if human_auth || presented_key.is_some() {
                    None
                } else {
                    extract_service(&req)
                };
                // The workspace this request acts in, from the trusted routing header.
                // Threaded into enrich so the membership check authorizes the SAME
                // workspace the router resolved (not a client-chosen one).
                let acting_workspace = extract_acting_workspace(&req);
                let ws = acting_workspace.as_deref();
                // The destination box (`x-route-pool`) → the signed contract's `aud`.
                let route_pool = extract_route_pool(&req);
                // The per-route requirements the tenant-router resolved (N4 phase 2).
                let requirements = extract_requirements(&req);
                // identity-existence-hiding: the per-route gate signals. A route is
                // *enriched* (private) when `x-auth-required` is true, and
                // *workspace-scoped* unless explicitly marked account-scoped. Both are
                // trusted-emitted; account-scoped absence is the fail-closed (gated)
                // state. Only an enriched, workspace-scoped route hides existence.
                let auth_required = trusted_flag(&req, HDR_AUTH_REQUIRED);
                let account_scoped = trusted_flag(&req, HDR_ACCOUNT_SCOPED);
                // RESOLUTION BRANCHES ON KIND (task 4.2): a user resolves via live
                // membership (existing path); a service resolves via the live platform
                // registry. Both fail closed to no `acting` when no authority resolves.
                // `sub` is a user identifier (PII): keep it out of per-request info logs.
                let (enriched, result): (Enriched<'_>, &'static str) = if human_auth {
                    debug!(sub = %human_sub, "enrich subject");
                    let (profile, result) = match self.state.resolve(&human_sub).await {
                        Resolved::Found(p) => {
                            info!(kind = "user", hit = true, "enrich");
                            (Some(p), "hit")
                        }
                        // Authenticated but no profile row yet — a legitimate state
                        // (deny-by-default, spec R2); enrich without authz fields.
                        Resolved::Absent => {
                            info!(kind = "user", hit = false, "enrich");
                            (None, "miss")
                        }
                        // Store unreadable → suspension state is UNKNOWN. Fail closed
                        // by default so a suspended user can't slip through during a
                        // store outage; SIDECAR_FAIL_OPEN trades back to availability.
                        Resolved::Unavailable => {
                            if must_fail_closed(true, true, self.state.fail_open) {
                                warn!("store unavailable for authenticated request -> 503 (fail-closed)");
                                break 'decide (unavailable_503(), "unavailable_closed");
                            }
                            warn!("store unavailable for authenticated request -> enrich without profile (fail-open)");
                            (None, "unavailable_open")
                        }
                    };
                    // Workspace authority: a live membership of the acting workspace.
                    let acting = ws
                        .zip(profile.as_ref())
                        .and_then(|(w, p)| p.resolve_membership(w))
                        .map(Acting::Workspace);
                    (
                        Enriched {
                            sub: human_sub.as_str(),
                            kind: Some(PrincipalKind::User.as_str()),
                            on_behalf_of: None,
                            profile,
                            authenticated: true,
                            acting,
                        },
                        result,
                    )
                } else if let Some(candidate) = api_key_candidate.as_ref() {
                    // API-KEY principal (task 4.2): effective authority = the CREATING
                    // user's LIVE membership of the acting workspace ∩ the key's scopes.
                    // Resolve the creator's Profile (the same cache path the human uses)
                    // and run the pure-core intersection; empty ⇒ no acting ⇒ fail closed
                    // (task 4.3), matching the human unresolved path. `on_behalf_of` is
                    // the creator; the api-key carries no coarse global roles of its own
                    // (least-privilege — `profile: None`).
                    let creator_profile = match self.state.resolve(&candidate.creator_sub).await {
                        Resolved::Found(p) => Some(p),
                        // No creator profile / store unreadable ⇒ no live membership to
                        // intersect ⇒ the key resolves to no authority (rejected).
                        Resolved::Absent | Resolved::Unavailable => None,
                    };
                    let acting = ws
                        .and_then(|w| {
                            let creator_membership =
                                creator_profile.as_ref().and_then(|p| p.resolve_membership(w));
                            ScopeIntersectionResolver::resolve(candidate, w, creator_membership)
                        })
                        .and_then(|p| match p.authority {
                            Authority::Workspace(m) => Some(Acting::Workspace(m)),
                            Authority::Platform(_) => None,
                        });
                    // Audit (task 7.1): every key-authenticated request records BOTH the
                    // key id and the creating user, so an action is attributable to the
                    // human behind the automation. The presented secret is NEVER logged.
                    info!(
                        kind = "apikey",
                        key_id = %candidate.key_id,
                        on_behalf_of = %candidate.creator_sub,
                        resolved = acting.is_some(),
                        "enrich",
                    );
                    let result = if acting.is_some() { "apikey_hit" } else { "apikey_unresolved" };
                    (
                        Enriched {
                            sub: candidate.key_id.as_str(),
                            kind: Some(PrincipalKind::ApiKey.as_str()),
                            on_behalf_of: Some(candidate.creator_sub.as_str()),
                            profile: None,
                            authenticated: true,
                            acting,
                        },
                        result,
                    )
                } else if let Some(sid) = service_id.as_deref() {
                    // SERVICE principal (task 4.2): platform authority from the live
                    // registry. Absent/inactive/unconfigured → no authority (fail
                    // closed): no acting scope authored, no contract minted. A service
                    // always acts on ONE workspace per request, taken from the trusted
                    // `x-workspace-id` (never service-supplied); with no acting
                    // workspace there is nothing to act on, so it also fails closed.
                    let acting = self.state.resolve_platform_scope(sid).and_then(|scope| {
                        ws.map(|w| Acting::Platform {
                            workspace_id: w.to_owned(),
                            permissions: scope.permissions,
                        })
                    });
                    let result = if acting.is_some() { "svc_hit" } else { "svc_unresolved" };
                    info!(kind = "service", resolved = acting.is_some(), "enrich");
                    (
                        Enriched {
                            sub: sid,
                            kind: Some(PrincipalKind::Service.as_str()),
                            on_behalf_of: None,
                            profile: None,
                            authenticated: true,
                            acting,
                        },
                        result,
                    )
                } else {
                    // Truly anonymous (no human, no service credential). Don't touch the
                    // store — the subject is never a stored profile, so a lookup is a
                    // guaranteed miss that needlessly loads the pool on anonymous traffic.
                    info!(anonymous = true, "enrich");
                    (
                        Enriched {
                            sub: human_sub.as_str(),
                            kind: None,
                            on_behalf_of: None,
                            profile: None,
                            authenticated: human_auth,
                            acting: None,
                        },
                        "anonymous",
                    )
                };
                // identity-existence-hiding: hide the workspace from a NON-MEMBER
                // before the 403 requirements gate can reveal it. On an enriched,
                // workspace-scoped route acting on a resolved workspace, an unresolved
                // acting authority (no live membership of that workspace, across every
                // principal kind) is refused with a 404 that is indistinguishable from
                // a nonexistent workspace — so a caller with no relationship cannot
                // tell "forbidden" from "does not exist". A MEMBER who merely lacks a
                // required role/entitlement is NOT hidden: they fall through to the
                // honest 403 below (their membership already discloses existence).
                // Account-scoped routes (e.g. /me) and public routes are never gated.
                if hide_nonmember_as_404(
                    auth_required,
                    account_scoped,
                    ws.is_some(),
                    enriched.acting.is_some(),
                ) {
                    info!("non-member on a private workspace route -> 404 (existence-hiding)");
                    break 'decide (not_found_404(), "not_found");
                }
                // N4 phase-2 gate: every resolved requirement must be satisfied by
                // the enrichment computed above, else 403 before the backend.
                // jwt_authn upstream owns the anonymous-on-protected-route 401; an
                // anonymous request carrying requirement signals means something
                // upstream is misconfigured, and it denies here (fail-closed).
                if let Err(reason) = decide_route_requirements(
                    self.state.pdp.as_ref(),
                    &requirements,
                    enriched.profile.as_ref(),
                    enriched.authenticated,
                    &self.state.aal_levels,
                ) {
                    info!(reason = %reason, "route requirements unsatisfied -> 403");
                    break 'decide (forbidden_403(), "forbidden");
                }
                // workspace-plan-tier (task 3.3): resolve the acting workspace's plan from
                // the resident snapshot, but ONLY when an authority resolved — so the plan
                // is authored exactly where the acting scope is, and never for an
                // unresolved request. Owned here so it outlives the borrow handed to
                // `enrich_response`; `None` on an unknown workspace / unconfigured
                // projection omits the header and the claim (fail-soft, not a 503).
                let acting_plan: Option<String> = enriched
                    .acting
                    .as_ref()
                    .and(ws)
                    .and_then(|w| self.state.resolve_plan(w));
                // The active signer is a swap-able rotation target (automate-signing-key-
                // rotation): clone the current one up front so the Arc outlives the borrow
                // handed to `enrich_response`, and a mid-request rotation never tears.
                let active_signer = self.state.current_signer();
                (
                    enrich_response(
                        &enriched,
                        acting_plan.as_deref(),
                        &SignContext {
                            signer: active_signer.as_deref(),
                            route_pool: route_pool.as_deref(),
                            now: now_secs(),
                        },
                    ),
                    result,
                )
            }
        } else {
            warn!("not ready -> 503");
            (warming_503(), "not_ready")
        };
        // Outcome-aware RED: latency and the request counter share one `result`
        // attribute so latency is sliceable by outcome (the availability/latency SLO
        // depends on this) and both series stay label-consistent. `result` is a bounded
        // low-card enum already in the collector allow-list.
        let outcome = [KeyValue::new("result", result.to_owned())];
        METRICS.ext_proc_duration.record(started.elapsed().as_secs_f64(), &outcome);
        METRICS.ext_proc_requests.add(1, &outcome);
        Span::current().record("enrich.result", result);
        Some(resp)
    }
}

type RespStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<ProcessingResponse, Status>> + Send>>;

#[tonic::async_trait]
impl ExternalProcessor for Sidecar {
    type ProcessStream = RespStream;

    async fn process(
        &self,
        request: Request<Streaming<ProcessingRequest>>,
    ) -> Result<Response<Self::ProcessStream>, Status> {
        // Capture the edge's trace context from the ext_proc gRPC metadata before
        // consuming the stream; it parents every span for this request.
        let trace_meta = trace_metadata(request.metadata());
        let mut inbound = request.into_inner();
        let me = self.clone();
        let (tx, rx) = mpsc::channel(8);
        tokio::spawn(async move {
            while let Some(msg) = inbound.next().await {
                match msg {
                    Ok(req) => {
                        if let Some(resp) = me.handle(req, &trace_meta).await
                            && tx.send(Ok(resp)).await.is_err()
                        {
                            break;
                        }
                    }
                    Err(status) => {
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

// --------------------------------------------------------------------------- //
// Change-feed watcher (RFC C4): push live changes into the cache. Lazy warm —
// readiness means "store reachable + feed open" (RFC C6 revised), NOT that the
// whole population is resident; cold subjects load on demand via the miss-load.
// --------------------------------------------------------------------------- //
pub(crate) async fn watch_store(state: AppState) {
    // Resume cursor kept across reconnects so a feed blip replays the gap and
    // no change is missed (resumable feed, RFC C4). In-memory is sufficient: a
    // process restart starts with an empty cache, so there is nothing stale to
    // miss — only mid-process reconnects need to resume.
    let mut resume: Option<WatchToken> = None;
    loop {
        match run_watch(&state, &mut resume).await {
            Ok(()) => warn!("change feed ended; reconnecting"),
            Err(e) => warn!(error = %e, "watch error; retrying"),
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn run_watch(state: &AppState, resume: &mut Option<WatchToken>) -> Result<(), BoxError> {
    let mut stream = state.store.watch(resume.clone()).await?;
    info!(resuming = resume.is_some(), "watching change feed");
    // Store reachable + feed open => ready (lazy warm, no full replay).
    if !state.ready.swap(true, Ordering::Relaxed) {
        let ms = state.start.elapsed().as_millis() as u64;
        state.warm_ms.store(ms, Ordering::Relaxed);
        info!(time_to_warm_ms = ms, "READY");
    }
    while let Some(event) = stream.next().await {
        let event = event?;
        match event.change {
            Change::Upsert(p) => {
                // Bounded cache (RFC §6.3 revised): only refresh entries we are
                // actually serving; cold subjects load on demand. This keeps a
                // resident suspension/role change instant for active users (C11)
                // without pulling the whole population into memory.
                let key = p.sub.clone();
                if state.cache.contains_key(&key) {
                    state.cache.insert(key, Arc::new(*p)).await;
                }
                METRICS.kv_updates.add(1, &[KeyValue::new("op", "upsert")]);
            }
            Change::Delete(sub) => {
                state.cache.invalidate(&sub).await;
                METRICS.kv_updates.add(1, &[KeyValue::new("op", "delete")]);
            }
        }
        // Remember the resume position so a reconnect picks up right here.
        *resume = Some(event.token);
        state.last_apply_ms.store(now_ms(), Ordering::Relaxed);
    }
    Ok(())
}

// --------------------------------------------------------------------------- //
// Platform-service registry watcher (normalized-principal ADR-7, task 2.3): keep the
// RESIDENT active-service map fresh off the `platform.services` change feed, so a
// register/permission-change/revoke lands within seconds — the same liveness the human
// membership path gets. The registry is small (a handful of core services), so each
// signal reloads the WHOLE active set rather than a per-key miss-load.
// --------------------------------------------------------------------------- //
pub(crate) async fn watch_platform_services(
    url: String,
    poll: Duration,
    tx: watch::Sender<Arc<HashMap<String, PlatformScope>>>,
) {
    loop {
        // Connect (retrying) — a SELECT-only pool for reloads + its own LISTEN
        // connection. The feed re-primes the snapshot on every (re)open, so a blip
        // does not clear the last-known map (a service stays resolvable during a short
        // outage, mirroring the profile cache); only a cold start with the store
        // unreachable leaves the map empty → every service fails closed.
        let reader = match PgPlatformServiceReader::connect(&url).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "platform registry connect failed; retrying");
                sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        match reader.watch_active(&url, poll).await {
            Ok(mut feed) => {
                info!("watching platform-service registry");
                while let Some(item) = feed.next().await {
                    match item {
                        Ok(services) => {
                            let map: HashMap<String, PlatformScope> = services
                                .into_iter()
                                .map(|s| (s.service_id, s.scope))
                                .collect();
                            info!(active = map.len(), "platform registry refreshed");
                            let _ = tx.send(Arc::new(map));
                        }
                        Err(e) => {
                            warn!(error = %e, "platform registry feed error; reconnecting");
                            break;
                        }
                    }
                }
            }
            Err(e) => warn!(error = %e, "platform registry watch failed; retrying"),
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Refresh the resident `workspace_id` → plan snapshot off the routing plane's workspace
/// change feed (`workspace-plan-tier` task 3.1) — the plan twin of
/// [`watch_platform_services`]. The feed re-primes the whole set on every (re)open, so a
/// blip keeps the last-known map (a workspace stays resolvable during a short outage,
/// mirroring the profile cache); only a cold start with the routing store unreachable
/// leaves the map empty → every workspace resolves to no plan (omitted, fail-soft).
pub(crate) async fn watch_workspace_plans(
    url: String,
    poll: Duration,
    tx: watch::Sender<Arc<HashMap<String, String>>>,
) {
    loop {
        let reader = match PgWorkspacePlanReader::connect(&url).await {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "workspace-plan store connect failed; retrying");
                sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        match reader.watch_active(&url, poll).await {
            Ok(mut feed) => {
                info!("watching workspace-plan set");
                while let Some(item) = feed.next().await {
                    match item {
                        Ok(plans) => {
                            let map: HashMap<String, String> = plans
                                .into_iter()
                                .map(|p| (p.workspace_id, p.plan))
                                .collect();
                            info!(workspaces = map.len(), "workspace-plan set refreshed");
                            let _ = tx.send(Arc::new(map));
                        }
                        Err(e) => {
                            warn!(error = %e, "workspace-plan feed error; reconnecting");
                            break;
                        }
                    }
                }
            }
            Err(e) => warn!(error = %e, "workspace-plan watch failed; retrying"),
        }
        sleep(Duration::from_secs(2)).await;
    }
}

/// Resolves when the process receives SIGINT or (on unix) SIGTERM.
pub(crate) async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) =
            signal::unix::signal(signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    info!("shutdown signal received");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::*;
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use moka::future::Cache;
    use tokio::net::TcpListener;
    use tonic::transport::Server;
    use envoy_types::pb::envoy::service::ext_proc::v3::{
        external_processor_server::ExternalProcessorServer, HttpHeaders,
    };
    use identity_core::store::{ChangeFeed, ProfileStore};
    use identity_core::Profile;
    use crate::state::{parse_aal_levels, DEFAULT_AAL_LEVELS};

    /// adopt-cedar-policy-gate task 4.2 — decision ORDERING is preserved: the 404
    /// existence-hide fires BEFORE the PDP 403. A non-member of a private, workspace-
    /// scoped route (`acting_resolved = false`) is hidden as a 404 and the gate is never
    /// reached; a MEMBER (`acting_resolved = true`) who merely lacks a required role is
    /// NOT hidden and falls through to the PDP, which denies → 403. (The 503 fail-closed
    /// sits further up and is asserted unchanged by `unavailable_503_is_a_blocking_503`.)
    #[test]
    fn decision_ordering_404_hides_nonmember_before_pdp_403() {
        let pdp = test_pdp();
        let levels = levels();
        let admin_route = reqs(Some("admin"), None, None);

        // Non-member on an enriched, workspace-scoped route → hidden as 404 (the gate,
        // and thus the PDP, is never consulted).
        assert!(
            hide_nonmember_as_404(true, false, true, false),
            "a non-member must be hidden as 404 before the 403 gate",
        );

        // A MEMBER (acting resolved) lacking the required role is NOT hidden…
        assert!(
            !hide_nonmember_as_404(true, false, true, true),
            "a member is not hidden — they reach the honest 403",
        );
        // …and the PDP then denies that member → 403.
        let viewer = gated_profile(&["viewer"], &[]);
        assert!(
            decide_route_requirements(pdp.as_ref(), &admin_route, Some(&viewer), true, &levels)
                .is_err(),
            "a member lacking the required role is denied by the PDP (403)",
        );
    }

    /// The ext_proc gRPC stream is EXEMPT from the per-request timeout: one
    /// stream serves a trusted Envoy connection for its lifetime, so it must
    /// stay open well past the bound the HTTP surfaces enforce and keep
    /// processing messages. Serves the REAL tonic service construction main()
    /// uses, on an ephemeral port.
    #[tokio::test]
    async fn ext_proc_stream_survives_past_the_http_request_timeout() {
        use envoy_types::pb::envoy::service::ext_proc::v3::external_processor_client::ExternalProcessorClient;
        use futures::stream::pending as pending_stream;
        use tokio_stream::wrappers::TcpListenerStream;

        /// Store stub: the anonymous enrich path never reads it; watch never yields.
        struct NoStore;
        #[tonic::async_trait]
        impl ProfileStore for NoStore {
            async fn get(&self, _sub: &str) -> Result<Option<Profile>, BoxError> {
                Ok(None)
            }
            async fn put(&self, _profile: &Profile) -> Result<(), BoxError> {
                Ok(())
            }
            async fn delete(&self, _sub: &str) -> Result<(), BoxError> {
                Ok(())
            }
            async fn scan_all(&self) -> Result<Vec<Profile>, BoxError> {
                Ok(vec![])
            }
            async fn watch(&self, _after: Option<WatchToken>) -> Result<ChangeFeed, BoxError> {
                Ok(Box::pin(pending_stream()))
            }
        }

        let state = AppState {
            cache: Cache::new(16),
            store: Arc::new(NoStore),
            ready: Arc::new(AtomicBool::new(true)),
            last_apply_ms: Arc::new(AtomicU64::new(0)),
            warm_ms: Arc::new(AtomicU64::new(0)),
            start: Instant::now(),
            fail_open: false,
            aal_levels: Arc::new(parse_aal_levels(DEFAULT_AAL_LEVELS)),
            pdp: test_pdp(),
            signer: None,
            platform: None,
            plans: None,
            api_keys: None,
        };

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let incoming = TcpListenerStream::new(listener);
        drop(tokio::spawn(async move {
            Server::builder()
                .add_service(ExternalProcessorServer::new(Sidecar { state }))
                .serve_with_incoming(incoming)
                .await
                .unwrap();
        }));

        let mut client = loop {
            match ExternalProcessorClient::connect(format!("http://{addr}")).await {
                Ok(conn) => break conn,
                Err(_) => sleep(Duration::from_millis(50)).await,
            }
        };

        // Much tighter than the 30s production default, to keep the test fast:
        // the stream must outlive this HTTP-surface bound with room to spare.
        let http_timeout = Duration::from_millis(300);

        let (tx, rx) = mpsc::channel::<ProcessingRequest>(4);
        let mut stream = client
            .process(ReceiverStream::new(rx))
            .await
            .unwrap()
            .into_inner();
        let headers_msg = || ProcessingRequest {
            request: Some(processing_request::Request::RequestHeaders(HttpHeaders::default())),
            ..Default::default()
        };

        tx.send(headers_msg()).await.unwrap();
        assert!(
            stream.message().await.unwrap().is_some(),
            "the stream must process its first message",
        );

        // Hold the stream open well past the per-request timeout the HTTP
        // surfaces enforce — no deadline may fire on the gRPC stream.
        sleep(http_timeout * 4).await;

        tx.send(headers_msg()).await.unwrap();
        assert!(
            stream.message().await.unwrap().is_some(),
            "the stream must still process messages after outliving the HTTP request timeout",
        );
    }

}
