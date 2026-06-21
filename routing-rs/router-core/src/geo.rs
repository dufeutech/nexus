//! Edge geo / network context — the SYSTEM-OWNED normalized contract (vendor-free).
//!
//! An upstream edge (a CDN / front proxy) MAY attach per-request geo + network
//! signals (country, city, client IP, …). This module owns two things and nothing
//! else: the normalized shape we consume (`GeoContext`) and the pure mapping from
//! it to the trusted `x-geo-*` request headers a backend reads. It is deliberately
//! ignorant of *which* upstream produced the signals: the SOURCE-specific header
//! names are a vendor concern and are extracted in the edge adapter, then handed in
//! here already split into fields (rules §2/§5: no vendor concretion in core;
//! RFC §3.8: identifiers arriving from an external provider are mapped to the
//! normalized form AT THE BOUNDARY, so everything downstream stays uniform).
//!
//! Every value is re-normalized here before it is emitted — the input is treated
//! as untrusted-shaped text (it transited the network), so a field that does not
//! pass its rule is simply dropped, never forwarded raw. The output header names
//! are the only trusted ones; client-supplied copies MUST be stripped at the edge
//! before resolution runs (RFC C3), exactly as for `x-tenant-*` / `x-user-*`.

/// Free-text geo fields are capped to a sane length so a hostile/garbage upstream
/// value cannot bloat the forwarded header set.
const MAX_TEXT_LEN: usize = 64;

/// The complete set of trusted headers `to_headers` can emit. The edge strip list
/// (RFC C3) MUST remove every one of these from client input; the parity test
/// below pins that `to_headers` never emits a name outside this set.
pub const TRUSTED_HEADERS: &[&str] = &[
    "x-geo-country",
    "x-geo-continent",
    "x-geo-region",
    "x-geo-city",
    "x-geo-postal-code",
    "x-geo-timezone",
    "x-geo-latitude",
    "x-geo-longitude",
    "x-geo-client-ip",
];

/// The normalized per-request geo / network context, one optional field per
/// signal we consume. Fields are the *raw* values as extracted at the boundary;
/// normalization + validation happen in [`GeoContext::to_headers`], so a caller
/// can build this struct straight from source headers without pre-cleaning.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GeoContext {
    /// ISO-3166-1 alpha-2 country code (also carries upstream sentinels like
    /// `XX` = unknown, `T1` = Tor).
    pub country: Option<String>,
    /// Continent code (e.g. `NA`, `EU`).
    pub continent: Option<String>,
    /// Region / subdivision name.
    pub region: Option<String>,
    /// City name.
    pub city: Option<String>,
    /// Postal / ZIP code.
    pub postal_code: Option<String>,
    /// IANA timezone (e.g. `America/Los_Angeles`).
    pub timezone: Option<String>,
    /// Latitude, as text; emitted only if it parses as a finite number.
    pub latitude: Option<String>,
    /// Longitude, as text; emitted only if it parses as a finite number.
    pub longitude: Option<String>,
    /// The originating client IP as seen by the edge.
    pub client_ip: Option<String>,
}

impl GeoContext {
    /// Normalize every present field and project it onto its trusted header name.
    /// A field that fails its rule is dropped (not emitted), so the result holds
    /// only clean, system-owned attributes. Pure and deterministic: the same
    /// context always yields the same headers, in a fixed order.
    pub fn to_headers(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        let mut push = |name: &'static str, value: Option<String>| {
            if let Some(v) = value {
                out.push((name, v));
            }
        };
        // Short codes: ASCII-alphanumeric, length-capped, uppercased.
        push("x-geo-country", self.country.as_deref().and_then(|s| norm_code(s, 2)));
        push("x-geo-continent", self.continent.as_deref().and_then(|s| norm_code(s, 2)));
        // Free text: trimmed, control chars dropped, length-capped, non-empty.
        push("x-geo-region", self.region.as_deref().and_then(norm_text));
        push("x-geo-city", self.city.as_deref().and_then(norm_text));
        push("x-geo-postal-code", self.postal_code.as_deref().and_then(norm_text));
        push("x-geo-timezone", self.timezone.as_deref().and_then(norm_text));
        // Coordinates: must parse as a finite number; re-emitted canonical.
        push("x-geo-latitude", self.latitude.as_deref().and_then(norm_coord));
        push("x-geo-longitude", self.longitude.as_deref().and_then(norm_coord));
        // Client IP: single token, no whitespace/control, length-capped.
        push("x-geo-client-ip", self.client_ip.as_deref().and_then(norm_ip));
        out
    }
}

/// Short code (country/continent): ASCII-alphanumeric only, at most `max` bytes,
/// uppercased. Rejects empty/overlong/non-alphanumeric input.
fn norm_code(raw: &str, max: usize) -> Option<String> {
    let v = raw.trim();
    if v.is_empty() || v.len() > max || !v.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    Some(v.to_ascii_uppercase())
}

/// Free-text geo field: drop control characters, trim, cap length, require
/// non-empty. Internal spaces are kept (e.g. `New York`).
fn norm_text(raw: &str) -> Option<String> {
    let cleaned: String = raw.chars().filter(|c| !c.is_control()).collect();
    let v = cleaned.trim();
    if v.is_empty() || v.len() > MAX_TEXT_LEN {
        return None;
    }
    Some(v.to_string())
}

/// Coordinate: must parse as a finite floating-point number; re-emit the canonical
/// text form so a garbage value can never reach the backend.
fn norm_coord(raw: &str) -> Option<String> {
    match raw.trim().parse::<f64>() {
        Ok(n) if n.is_finite() => Some(n.to_string()),
        _ => None,
    }
}

/// Client IP: a single token with no whitespace/control characters, length-capped
/// to comfortably fit an IPv6 form. Not a full IP parse — just a safety sanitizer.
fn norm_ip(raw: &str) -> Option<String> {
    let v = raw.trim();
    if v.is_empty() || v.len() > 64 || v.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) {
        return None;
    }
    Some(v.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_and_continent_are_uppercased_and_length_guarded() {
        let g = GeoContext {
            country: Some("us".into()),
            continent: Some("na".into()),
            ..Default::default()
        };
        let h = g.to_headers();
        assert!(h.contains(&("x-geo-country", "US".to_string())));
        assert!(h.contains(&("x-geo-continent", "NA".to_string())));

        // Overlong / non-alphanumeric codes are dropped, not forwarded raw.
        let bad = GeoContext {
            country: Some("USA".into()),
            continent: Some("e!".into()),
            ..Default::default()
        };
        assert!(bad.to_headers().is_empty());
    }

    #[test]
    fn upstream_sentinels_are_preserved() {
        // `XX` (unknown) and `T1` (Tor) are valid 2-char codes and must survive.
        let g = GeoContext { country: Some("t1".into()), ..Default::default() };
        assert_eq!(g.to_headers(), vec![("x-geo-country", "T1".to_string())]);
    }

    #[test]
    fn free_text_is_trimmed_control_stripped_and_capped() {
        let g = GeoContext {
            city: Some("  New York\r\n ".into()),       // space kept; CRLF stripped
            region: Some(" ".into()),                  // whitespace-only → dropped
            postal_code: Some("x".repeat(65)),         // overlong → dropped
            ..Default::default()
        };
        let h = g.to_headers();
        assert!(h.contains(&("x-geo-city", "New York".to_string())));
        assert!(!h.iter().any(|(k, _)| *k == "x-geo-region"));
        assert!(!h.iter().any(|(k, _)| *k == "x-geo-postal-code"));
    }

    #[test]
    fn coordinates_must_be_finite_numbers() {
        let g = GeoContext {
            latitude: Some("37.77".into()),
            longitude: Some("not-a-number".into()),
            ..Default::default()
        };
        let h = g.to_headers();
        assert!(h.contains(&("x-geo-latitude", "37.77".to_string())));
        assert!(!h.iter().any(|(k, _)| *k == "x-geo-longitude"));
    }

    #[test]
    fn client_ip_rejects_whitespace() {
        let ok = GeoContext { client_ip: Some(" 2001:db8::1 ".into()), ..Default::default() };
        assert_eq!(ok.to_headers(), vec![("x-geo-client-ip", "2001:db8::1".to_string())]);

        let bad = GeoContext { client_ip: Some("1.2.3.4 5.6.7.8".into()), ..Default::default() };
        assert!(bad.to_headers().is_empty());
    }

    #[test]
    fn empty_context_emits_nothing() {
        assert!(GeoContext::default().to_headers().is_empty());
    }

    #[test]
    fn every_emitted_name_is_a_declared_trusted_header() {
        // A fully-populated context must only ever emit names from TRUSTED_HEADERS,
        // so the edge strip list (C3) can be kept in lockstep with this contract.
        let g = GeoContext {
            country: Some("US".into()),
            continent: Some("NA".into()),
            region: Some("California".into()),
            city: Some("San Francisco".into()),
            postal_code: Some("94107".into()),
            timezone: Some("America/Los_Angeles".into()),
            latitude: Some("37.77".into()),
            longitude: Some("-122.41".into()),
            client_ip: Some("203.0.113.7".into()),
        };
        let emitted: Vec<&str> = g.to_headers().into_iter().map(|(k, _)| k).collect();
        assert_eq!(emitted.len(), TRUSTED_HEADERS.len());
        for name in emitted {
            assert!(TRUSTED_HEADERS.contains(&name), "{name} not in TRUSTED_HEADERS");
        }
    }
}
