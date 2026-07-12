use std::collections::HashMap;

use tonic::metadata::MetadataMap;

use envoy_types::pb::envoy::service::ext_proc::v3::{processing_request, ProcessingRequest};

use router_core::context::ClientContext;
use router_core::geo::GeoContext;

// --------------------------------------------------------------------------- //
// Host extraction from the request headers (the routing key). Prefer the HTTP/2
// `:authority` pseudo-header, fall back to `Host`.
// --------------------------------------------------------------------------- //
// --------------------------------------------------------------------------- //
// Trace-context continuation (first-party-telemetry). The edge injects a W3C
// `traceparent` (edge-rooted, carrying its head-sampling flag) into the request
// headers that arrive here. Extract it so the router's processing span parents
// under the edge trace — closing the first-party hole between edge and backend.
// Only the two W3C headers are read (cheap); the sampled flag is honored by the
// ParentBased sampler, so a not-sampled request produces no exported span.
// --------------------------------------------------------------------------- //
// The edge propagates each request's trace context as gRPC METADATA on the ext_proc
// call (it traces the call itself as an egress span). The ext_proc HTTP headers do
// NOT carry `traceparent` at this point — the edge injects that toward the backend
// AFTER the ext_proc filters run — so the gRPC metadata is the correct source. One
// ext_proc gRPC stream per HTTP request, so this metadata is this request's context.
pub(crate) fn trace_metadata(metadata: &MetadataMap) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for name in ["traceparent", "tracestate"] {
        if let Some(value) = metadata.get(name).and_then(|value| value.to_str().ok()) {
            out.push((name.to_owned(), value.to_owned()));
        }
    }
    out
}

pub(crate) fn extract_host(req: &ProcessingRequest) -> Option<String> {
    let headers = match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => h.headers.as_ref()?,
        _ => return None,
    };
    let mut authority = None;
    let mut host = None;
    for hv in &headers.headers {
        let key = hv.key.to_ascii_lowercase();
        if key == ":authority" || key == "host" {
            let val = if hv.raw_value.is_empty() {
                hv.value.clone()
            } else {
                String::from_utf8_lossy(&hv.raw_value).into_owned()
            };
            if key == ":authority" {
                authority = Some(val);
            } else {
                host = Some(val);
            }
        }
    }
    authority.or(host)
}

// --------------------------------------------------------------------------- //
// Request path extraction (RFC N4): the second half of the auth-policy key. Read
// the HTTP/2 `:path` pseudo-header and strip the query string + fragment, so the
// policy matches on the path alone (`/app?x=1` resolves as `/app`). Defaults to
// `/` when absent so a path-less request still resolves the tenant default.
//
// SECURITY: the edge Envoy canonicalizes :path (normalize_path + merge_slashes +
// path_with_escaped_slashes_action: UNESCAPE_AND_FORWARD) BEFORE this ext_proc
// runs, so the path matched against the auth policy is already dot-segment- and
// %2F-normalized and agrees with what the backend receives. This avoids auth-gate
// path confusion (e.g. `/public%2f..%2fadmin`). Do NOT front the tenant-router
// with a proxy that leaves :path un-normalized.
// --------------------------------------------------------------------------- //
pub(crate) fn extract_path(req: &ProcessingRequest) -> String {
    let headers = match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => match h.headers.as_ref() {
            Some(h) => h,
            None => return "/".to_owned(),
        },
        _ => return "/".to_owned(),
    };
    for hv in &headers.headers {
        if hv.key.eq_ignore_ascii_case(":path") {
            let raw = if hv.raw_value.is_empty() {
                hv.value.clone()
            } else {
                String::from_utf8_lossy(&hv.raw_value).into_owned()
            };
            let path = raw.split(['?', '#']).next().unwrap_or("/");
            return if path.is_empty() { "/".to_owned() } else { path.to_owned() };
        }
    }
    "/".to_owned()
}

// --------------------------------------------------------------------------- //
// Cloudflare geo/network normalization (the SOURCE side of the boundary).
//
// When Cloudflare fronts the origin it attaches per-request signals as `cf-*`
// headers. We map ONLY the ones we consume onto the system-owned, vendor-free
// `x-geo-*` contract (router_core::geo), which re-normalizes every value before
// it is emitted. The Cloudflare header *names* are a vendor concern and live here
// in the adapter, never in core (rules §2/§5).
//
// Gated on presence: if no Cloudflare signature header (`cf-ray`, or
// `cf-connecting-ip`) is seen we return `None` and inject nothing, so a
// non-Cloudflare deployment is an exact no-op.
//
// TRUST: `cf-*` are trustworthy ONLY for requests that genuinely transited
// Cloudflare. The deployment MUST guarantee that at the true edge (Cloudflare
// Authenticated Origin Pulls / an IP allowlist) — the same standing assumption
// that lets the chain trust any forwarded header. We do not re-derive that trust
// here; we only normalize. The injected `x-geo-*` are stripped from client input
// upstream (RFC C3), so the backend trusts only what we set.
// --------------------------------------------------------------------------- //
pub(crate) fn extract_geo(req: &ProcessingRequest) -> Option<GeoContext> {
    let headers = match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => h.headers.as_ref()?,
        _ => return None,
    };
    // Collect the `cf-*` headers (lowercased, prefix dropped) in a single pass.
    let mut cf: HashMap<String, String> = HashMap::new();
    for hv in &headers.headers {
        let key = hv.key.to_ascii_lowercase();
        if let Some(name) = key.strip_prefix("cf-") {
            let val = if hv.raw_value.is_empty() {
                hv.value.clone()
            } else {
                String::from_utf8_lossy(&hv.raw_value).into_owned()
            };
            cf.insert(name.to_owned(), val);
        }
    }
    // Only act when Cloudflare actually fronted this request.
    if !cf.contains_key("ray") && !cf.contains_key("connecting-ip") {
        return None;
    }
    let take = |k: &str| cf.get(k).cloned();
    Some(GeoContext {
        country: take("ipcountry"),
        continent: take("ipcontinent"),
        region: take("region"),
        city: take("ipcity"),
        postal_code: take("postal-code"),
        timezone: take("timezone"),
        latitude: take("iplatitude"),
        longitude: take("iplongitude"),
        client_ip: take("connecting-ip"),
    })
}

/// Normalize the standards-based request-context signals into the trusted
/// `x-locale` / `x-lang` / `x-currency` / `x-privacy-*` / `x-device-type` set
/// (`router_core::context`). Source header names are an adapter concern and live
/// here; `country` (already-normalized geo country) feeds the ISO-4217 currency
/// derivation. Always present (at least `x-device-type: unknown`).
pub(crate) fn extract_client_context(req: &ProcessingRequest, country: Option<&str>) -> Vec<(&'static str, String)> {
    let headers = match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => match h.headers.as_ref() {
            Some(h) => h,
            None => return Vec::new(),
        },
        _ => return Vec::new(),
    };
    // Collect only the headers we consume (lowercased keys), in one pass.
    const WANTED: &[&str] = &["accept-language", "sec-gpc", "dnt", "sec-ch-ua-mobile", "user-agent"];
    let mut found: HashMap<String, String> = HashMap::new();
    for hv in &headers.headers {
        let key = hv.key.to_ascii_lowercase();
        if WANTED.contains(&key.as_str()) {
            let val = if hv.raw_value.is_empty() {
                hv.value.clone()
            } else {
                String::from_utf8_lossy(&hv.raw_value).into_owned()
            };
            found.insert(key, val);
        }
    }
    let g = |k: &str| found.get(k).map(String::as_str);
    ClientContext {
        accept_language: g("accept-language"),
        sec_gpc: g("sec-gpc"),
        dnt: g("dnt"),
        sec_ch_ua_mobile: g("sec-ch-ua-mobile"),
        user_agent: g("user-agent"),
        country,
    }
    .to_headers()
}

/// The header names carried on an incoming ext_proc `RequestHeaders` message (as
/// received), for the trusted-family strip. Empty for any other message kind.
pub(crate) fn request_header_names(req: &ProcessingRequest) -> Vec<&str> {
    match &req.request {
        Some(processing_request::Request::RequestHeaders(h)) => h
            .headers
            .as_ref()
            .map(|hm| hm.headers.iter().map(|hv| hv.key.as_str()).collect())
            .unwrap_or_default(),
        _ => Vec::new(),
    }
}
