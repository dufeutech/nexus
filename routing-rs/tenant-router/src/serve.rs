use std::env::var;
#[cfg(not(unix))]
use std::future::pending;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::StreamExt;
use tokio::signal;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};
use tracing::{info, info_span, warn};
use tracing::field::Empty;
use tracing::Instrument as _;
use tracing::Span;
use opentelemetry::KeyValue;

use envoy_types::pb::envoy::service::ext_proc::v3::{
    external_processor_server::ExternalProcessor, processing_request, ProcessingRequest,
    ProcessingResponse,
};

use router_core::telemetry;
use router_core::store::{BoxError, Invalidations};

use crate::state::{now_ms, AppState, METRICS};
use crate::extract::{
    extract_client_context, extract_geo, extract_host, extract_path, trace_metadata,
};
use crate::response::{auth_signals, reject_unknown_host, route_response, warming_503};

// --------------------------------------------------------------------------- //
// ext_proc service.
// --------------------------------------------------------------------------- //
#[derive(Clone)]
pub(crate) struct Router {
    pub(crate) state: AppState,
}

impl Router {
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
        // (or, absent one, roots per the sampler). `result` is recorded on it after
        // resolution for the trace view; the `info!` events inside are trace-stamped
        // by the log appender, giving the two-way logs↔traces pivot.
        let span = info_span!("router.resolve", route.result = Empty, otel.kind = "server");
        telemetry::continue_trace(&span, trace_meta.to_vec());
        self.resolve(req).instrument(span).await
    }

    async fn resolve(&self, req: ProcessingRequest) -> Option<ProcessingResponse> {
        let started = Instant::now();
        let (resp, result) = if self.state.ready.load(Ordering::Relaxed) {
            let host = extract_host(&req).unwrap_or_default();
            if let Some(d) = self.state.resolve(&host).await {
                // Assemble trusted request-context annotations. Edge geo
                // (Cloudflare) is presence-gated (no-op off Cloudflare); the
                // standards-based context (locale/currency/privacy/device) is
                // always evaluated. The normalized geo country feeds currency.
                let mut extra: Vec<(&'static str, String)> = Vec::new();
                // Per-route auth policy (RFC N4): resolve the request path
                // against the tenant's cached policy and emit the authoritative
                // signals the edge acts on — the boolean gate jwt_authn branches
                // on, plus the phase-2 requirement signals the identity sidecar
                // enforces (emitted only when set; see `auth_signals`).
                let path = extract_path(&req);
                extra.extend(auth_signals(&d.auth.resolve(&path)));
                let geo = extract_geo(&req).map(|g| g.to_headers()).unwrap_or_default();
                let country = geo
                    .iter()
                    .find(|(k, _)| *k == "x-geo-country")
                    .map(|(_, v)| v.clone());
                if !geo.is_empty() {
                    extra.push(("x-geo-source", "cloudflare".to_owned()));
                    extra.extend(geo);
                }
                extra.extend(extract_client_context(&req, country.as_deref()));
                info!(host = %host, workspace = %d.workspace_id, pool = d.pool.as_str(), annotations = extra.len(), "route");
                (route_response(&req, &d, &extra), "hit")
            } else {
                // Debug-format (escapes control/ESC bytes): this is the RAW,
                // un-normalized :authority — the reject branch is exactly where a
                // host `normalize_host` refused can carry log-corrupting bytes.
                info!(host = ?host, "reject: no tenant");
                (reject_unknown_host(), "reject")
            }
        } else {
            warn!("not ready -> 503");
            (warming_503(), "not_ready")
        };
        // Outcome-aware RED: latency and the request counter share one `result`
        // attribute so latency is sliceable by outcome (the availability/latency SLO
        // depends on this) and both series stay label-consistent. `result` is a bounded
        // low-card enum (hit/reject/not_ready) already in the collector allow-list.
        let outcome = [KeyValue::new("result", result.to_owned())];
        METRICS.ext_proc_duration.record(started.elapsed().as_secs_f64(), &outcome);
        METRICS.ext_proc_requests.add(1, &outcome);
        Span::current().record("route.result", result);
        Some(resp)
    }
}

type RespStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<ProcessingResponse, Status>> + Send>>;

#[tonic::async_trait]
impl ExternalProcessor for Router {
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
// Invalidation watcher (RFC C16): evict invalidated keys from every cache tier.
// Readiness means "store reachable + feed subscribed" — NOT a full table load
// (the routing set is too large to hold resident; lazy on-demand resolution).
// --------------------------------------------------------------------------- //
pub(crate) async fn watch_invalidations(state: AppState, invs: Arc<dyn Invalidations>) {
    loop {
        match run_invalidations(&state, invs.as_ref()).await {
            Ok(()) => warn!("invalidation feed ended; reconnecting"),
            Err(e) => warn!(error = %e, "invalidation feed error; retrying"),
        }
        sleep(Duration::from_secs(2)).await;
    }
}

async fn run_invalidations(state: &AppState, invs: &dyn Invalidations) -> Result<(), BoxError> {
    let mut feed = invs.subscribe().await?;
    info!("subscribed to invalidation feed");
    if !state.ready.swap(true, Ordering::Relaxed) {
        let ms = state.start.elapsed().as_millis() as u64;
        state.warm_ms.store(ms, Ordering::Relaxed);
        info!(time_to_warm_ms = ms, "READY");
    }
    while let Some(item) = feed.next().await {
        let domain = item?;
        // Exact-domain entries evict precisely. Wildcard-child entries cached
        // under a requested host self-heal via the L1/L2 TTL (RFC §3.10 staleness
        // backstop) — routing has no per-second revocation requirement.
        state.l1.invalidate(&domain).await;
        if let Some(l2) = &state.l2
            && let Err(e) = l2.invalidate(&domain).await
        {
            warn!(error = %e, "L2 invalidate failed");
        }
        METRICS.invalidations.add(1, &[]);
        state.last_apply_ms.store(now_ms(), Ordering::Relaxed);
        info!(domain = %domain, "invalidated");
    }
    Ok(())
}

pub(crate) fn env(key: &str, default: &str) -> String {
    var(key).unwrap_or_else(|_| default.to_owned())
}

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
