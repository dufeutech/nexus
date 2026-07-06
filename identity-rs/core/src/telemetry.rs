//! telemetry — the ONE place the identity plane assembles observability.
//!
//! Every identity-plane binary (sidecar, sync-worker, reconciler, membership-sync)
//! calls [`init`] once at startup and holds the returned [`TelemetryGuard`] for the
//! process lifetime. This is the box-telemetry-contract made first-party: one
//! endpoint, all signals, standard resource identity, trace-correlated logs,
//! fail-open.
//!
//! Design contract (see openspec/changes/first-party-telemetry/design.md):
//! - ALL `opentelemetry*` types are confined to this module (the adapter boundary),
//!   so a pre-1.0 version bump is a two-file change (this + the routing-plane twin
//!   `router_core::telemetry`, which is kept byte-for-byte identical below the
//!   doc comment — edit both together).
//! - `RUST_LOG` / `LOG_FORMAT` keep their exact prior meaning (the stdout fmt layer
//!   is unchanged; it stays for `docker logs`).
//! - The OTLP endpoint is the standard `OTEL_EXPORTER_OTLP_ENDPOINT`. UNSET ⇒ no
//!   telemetry providers are built and the service logs exactly as it did before
//!   this change (the fail-open, opt-in default).
//! - Export is fail-open: exporter build failure downgrades to fmt-only (never a
//!   panic), and batch processors drop under back-pressure rather than block.

use std::collections::HashMap;
use std::env;
use std::fmt;

use opentelemetry::global;
use opentelemetry::propagation::Extractor;
use opentelemetry::trace::TracerProvider as _;
use opentelemetry::KeyValue;
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_otlp::{LogExporter, MetricExporter, SpanExporter};
use opentelemetry_sdk::Resource;
use opentelemetry_sdk::logs::SdkLoggerProvider;
use opentelemetry_sdk::metrics::SdkMeterProvider;
use opentelemetry_sdk::propagation::TraceContextPropagator;
use opentelemetry_sdk::trace::{Sampler, SdkTracerProvider};
use tracing_opentelemetry::OpenTelemetrySpanExt as _;
use tracing_subscriber::fmt::layer as fmt_layer;
use tracing_subscriber::layer::Layered;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{EnvFilter, Layer, Registry};

/// The standard OTLP collection endpoint variable (box-telemetry-contract). Unset
/// ⇒ telemetry export is off and the service runs exactly as before this change.
const ENDPOINT_ENV: &str = "OTEL_EXPORTER_OTLP_ENDPOINT";

/// The subscriber stack every layer is composed against: the `RUST_LOG` filter over
/// the registry. Naming it lets the fmt/OTLP layers live in one `Vec` (shared `S`).
type RegistryStack = Layered<EnvFilter, Registry>;

/// A type-erased layer over [`RegistryStack`] — lets json/plain fmt and the optional
/// OTLP layers share one vector without their concrete types leaking into the stack.
type BoxedLayer = Box<dyn Layer<RegistryStack> + Send + Sync>;

/// Providers held for the process lifetime; flushed on drop.
struct Providers {
    /// Span pipeline (OTLP traces → Tempo).
    tracer: SdkTracerProvider,
    /// Log pipeline (OTLP logs → Loki), trace-id stamped by the appender bridge.
    logger: SdkLoggerProvider,
    /// Metric pipeline (OTLP metrics → Prometheus); instruments join in Phase B.
    meter: SdkMeterProvider,
}

/// Returned by [`init`] and held by `main`. On drop it flushes and shuts down the
/// providers (best-effort — telemetry never affects the exit path).
#[must_use = "hold the guard for the process lifetime; dropping it stops telemetry"]
pub struct TelemetryGuard {
    /// `Some` when OTLP export is active; `None` when logging to stdout only.
    providers: Option<Providers>,
}

impl fmt::Debug for TelemetryGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TelemetryGuard")
            .field("exporting", &self.providers.is_some())
            .finish()
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(providers) = self.providers.take() {
            // Best-effort flush; a telemetry shutdown error must never affect exit.
            if let Err(error) = providers.tracer.shutdown() {
                tracing::debug!(%error, "telemetry: tracer shutdown");
            }
            if let Err(error) = providers.logger.shutdown() {
                tracing::debug!(%error, "telemetry: logger shutdown");
            }
            if let Err(error) = providers.meter.shutdown() {
                tracing::debug!(%error, "telemetry: meter shutdown");
            }
        }
    }
}

/// Join `span` to the edge-rooted trace carried in `headers` — the W3C `traceparent`
/// (and `tracestate`) pairs the edge injects, names lowercased. Keeps every
/// `opentelemetry` type behind this adapter: the hot-path binary passes plain string
/// pairs and a `tracing::Span`, nothing else.
///
/// No-op when telemetry is disabled: with no propagator installed the extract yields
/// an empty context and the span simply roots locally (unexported by the no-op
/// tracer). The edge's head-sampling flag rides in `traceparent`, so a not-sampled
/// request produces a non-recording span (the `ParentBased` sampler honors it).
pub fn continue_trace(span: &tracing::Span, headers: Vec<(String, String)>) {
    /// Case-sensitive carrier over the already-lowercased header pairs.
    struct Carrier(HashMap<String, String>);
    impl Extractor for Carrier {
        fn get(&self, key: &str) -> Option<&str> {
            self.0.get(key).map(String::as_str)
        }
        fn keys(&self) -> Vec<&str> {
            self.0.keys().map(String::as_str).collect()
        }
        fn get_all(&self, key: &str) -> Option<Vec<&str>> {
            self.get(key).map(|value| vec![value])
        }
    }
    let carrier = Carrier(headers.into_iter().collect());
    let context = global::get_text_map_propagator(|propagator| propagator.extract(&carrier));
    if let Err(error) = span.set_parent(context) {
        // Fail-open: an un-parented span still records; never disrupt the hot path.
        tracing::debug!(%error, "telemetry: could not attach parent trace context");
    }
}

/// Log filter preserving every binary's prior convention: `RUST_LOG` if set, else
/// `LOG_LEVEL` (control-plane / sync-worker used this as the fallback level), else
/// `info`. Parsing is lossy — an invalid directive is dropped, never a panic.
fn env_filter() -> EnvFilter {
    if let Ok(filter) = EnvFilter::try_from_default_env() {
        return filter;
    }
    EnvFilter::new(env::var("LOG_LEVEL").unwrap_or_else(|_| "info".to_owned()))
}

/// A second filter for the OTLP *log* path: mute the telemetry stack's own crates
/// so exporting a log can't generate more logs (a feedback loop). Traces/metrics
/// are unaffected.
fn otel_log_filter() -> EnvFilter {
    EnvFilter::new("info")
        .add_directive("hyper=off".parse().unwrap_or_default())
        .add_directive("tonic=off".parse().unwrap_or_default())
        .add_directive("h2=off".parse().unwrap_or_default())
        .add_directive("tower=off".parse().unwrap_or_default())
        .add_directive("reqwest=off".parse().unwrap_or_default())
        .add_directive("opentelemetry=off".parse().unwrap_or_default())
}

/// The resource identity every signal carries. `service.name` is the code-provided
/// default (operators may override via `OTEL_SERVICE_NAME`); `service.version`
/// tracks the build; `deployment.environment.name` is supplied by operators through
/// `OTEL_RESOURCE_ATTRIBUTES` (both are merged in by the default resource detectors).
fn resource(service_name: &str) -> Resource {
    Resource::builder()
        .with_service_name(service_name.to_owned())
        .with_attribute(KeyValue::new("service.version", env!("CARGO_PKG_VERSION")))
        .build()
}

/// Build all three providers with OTLP/gRPC batch exporters. Fallible: a transport
/// build error propagates so the caller can fall back to fmt-only (fail-open).
/// # Errors
/// Returns the OTLP transport build error if any exporter (span/log/metric) cannot
/// be constructed; the caller downgrades to fmt-only logging (fail-open).
fn build_providers(service_name: &str) -> Result<Providers, opentelemetry_otlp::ExporterBuildError> {
    let res = resource(service_name);

    let span_exporter = SpanExporter::builder().with_tonic().build()?;
    let tracer = SdkTracerProvider::builder()
        // ParentBased(AlwaysOn): on the request hot path the edge always supplies a
        // parent, so this HONORS the edge's head-sampling flag (never overrides it —
        // spec: the edge's negative decision is respected). With no parent (a
        // background service rooting its own trace) it samples — always-on for the
        // low-volume background paths per design.
        .with_sampler(Sampler::ParentBased(Box::new(Sampler::AlwaysOn)))
        .with_resource(res.clone())
        .with_batch_exporter(span_exporter)
        .build();

    let log_exporter = LogExporter::builder().with_tonic().build()?;
    let logger = SdkLoggerProvider::builder()
        .with_resource(res.clone())
        .with_batch_exporter(log_exporter)
        .build();

    let metric_exporter = MetricExporter::builder().with_tonic().build()?;
    let meter = SdkMeterProvider::builder()
        .with_resource(res)
        .with_periodic_exporter(metric_exporter)
        .build();

    Ok(Providers {
        tracer,
        logger,
        meter,
    })
}

/// Initialize telemetry for `service_name` and install the process-global tracing
/// subscriber. Call exactly once, at the top of `main`, and keep the guard alive.
///
/// With `OTEL_EXPORTER_OTLP_ENDPOINT` set, spans/logs/metrics export over OTLP to
/// the collector and the stdout fmt layer stays for local debugging. Unset (or an
/// exporter that fails to build), the service logs exactly as before — no panic,
/// no new failure mode on the request path.
pub fn init(service_name: &str) -> TelemetryGuard {
    let json = env::var("LOG_FORMAT").is_ok_and(|value| value == "json");
    let endpoint_set = env::var(ENDPOINT_ENV).is_ok_and(|value| !value.trim().is_empty());

    // Build the OTel providers up front (only when an endpoint is configured); a
    // build failure downgrades to fmt-only rather than panicking (fail-open). The
    // global providers/propagator are installed here so `handle()` on the hot path
    // can extract the edge context and open spans against the global tracer.
    let mut build_error: Option<String> = None;
    let providers = if endpoint_set {
        match build_providers(service_name) {
            Ok(providers) => {
                global::set_text_map_propagator(TraceContextPropagator::new());
                global::set_tracer_provider(providers.tracer.clone());
                global::set_meter_provider(providers.meter.clone());
                Some(providers)
            }
            Err(error) => {
                build_error = Some(error.to_string());
                None
            }
        }
    } else {
        None
    };

    // ONE subscriber stack, assembled as a boxed-layer vector so the fmt layer's
    // field-formatter type (json vs plain) and the optional OTLP layers all share a
    // single `S` (`RegistryStack`). Reusing a layer value across separate `.with()`
    // chains pins its `S` to one arm and fails to unify (JsonFields vs DefaultFields).
    let stdout_layer: BoxedLayer = if json {
        Box::new(fmt_layer().json())
    } else {
        Box::new(fmt_layer())
    };
    let mut layers: Vec<BoxedLayer> = vec![stdout_layer];
    if let Some(active) = providers.as_ref() {
        layers.push(
            tracing_opentelemetry::layer()
                .with_tracer(active.tracer.tracer("identity-core"))
                .boxed(),
        );
        layers.push(
            OpenTelemetryTracingBridge::new(&active.logger)
                .with_filter(otel_log_filter())
                .boxed(),
        );
    }
    tracing_subscriber::registry()
        .with(env_filter())
        .with(layers)
        .init();

    if let Some(error) = build_error {
        tracing::warn!(%error, "telemetry: OTLP exporter build failed; logging to stdout only");
    } else if providers.is_some() {
        tracing::info!(
            endpoint = %env::var(ENDPOINT_ENV).unwrap_or_default(),
            "telemetry: OTLP export enabled (traces, metrics, logs)"
        );
    }
    TelemetryGuard { providers }
}
