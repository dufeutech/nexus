//! Host normalization (RFC §3.9) and wildcard parent derivation (RFC C14).
//!
//! Pure, total, deterministic functions: the same host always yields the same
//! key, with NO I/O — so the resolver, the control plane, and the tests all
//! agree on "what the cache/store key is."

/// Canonicalize a request host to its store/cache key: lowercased, a single
/// trailing dot removed, port removed. Total and deterministic (RFC §3.9
/// invariant).
///
/// Returns the **empty string** for any host that is not a valid, canonical
/// routing key — which the resolver and the cert-authorization gate both treat
/// as "no match" (fail closed). This is the load-bearing security property of
/// this function: the gate and the router share one key, so a host that cannot
/// be reduced to a single canonical form must not be reduced to *a* form (a
/// mismatch is exactly the "cert issued, then 404 / look-alike routes" failure).
///
/// Rejected (→ ""): embedded control characters or whitespace, empty labels
/// (`.x.com`, `a..b`, multiple trailing dots), and any non-ASCII byte. Internet
/// hostnames reach us as ASCII A-labels (TLS SNI is always an A-label, and Hosts
/// for IDNs are punycode), so a raw-Unicode host has no single canonical key
/// here and is refused rather than guessed at — callers that need IDN must
/// present the already-encoded `xn--…` form.
#[must_use]
pub fn normalize_host(raw: &str) -> String {
    let h = raw.trim();
    // Strip an optional port. Handle the bracketed IPv6 form `[::1]:8080` first,
    // then the common `host:port` form — only when the suffix is all digits, so
    // a bare IPv6 literal without a port is not truncated.
    let host = h.strip_prefix('[').map_or_else(
        // No bracket: a single colon means `host:port` — strip a numeric port.
        // More than one colon means a bare IPv6 literal (no brackets), which must
        // be left whole.
        || {
            h.split_once(':').map_or(h, |(before, suffix)| {
                if !suffix.contains(':')
                    && !suffix.is_empty()
                    && suffix.bytes().all(|b| b.is_ascii_digit())
                {
                    before
                } else {
                    h
                }
            })
        },
        // Bracketed IPv6: `[::1]` or `[::1]:8080` → the address inside the brackets.
        |rest| rest.split_once(']').map_or(h, |(addr, _)| addr),
    );
    // Strip at most ONE trailing (root-indicating) dot — a second one would leave
    // an empty final label, which `is_valid_host_key` then rejects.
    let key = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if is_valid_host_key(&key) {
        key
    } else {
        String::new()
    }
}

/// Whether a lowercased, port-stripped key is a valid canonical routing key.
/// LDH-plus-dot for DNS names (no empty labels), or a hex/colon IPv6 literal;
/// never any control char, whitespace, or non-ASCII byte.
fn is_valid_host_key(key: &str) -> bool {
    if key.is_empty() {
        return false;
    }
    // No control chars, no whitespace, no non-ASCII (DEL/0x7f and up rejected).
    if key.bytes().any(|b| b <= 0x20 || b >= 0x7f) {
        return false;
    }
    // IPv6 literal (the only key that legitimately contains a colon): hex + colon.
    if key.contains(':') {
        return key.bytes().all(|b| b.is_ascii_hexdigit() || b == b':');
    }
    // DNS name: no empty labels, and every char is letter/digit/hyphen/dot.
    if key.split('.').any(str::is_empty) {
        return false;
    }
    key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
}

/// The parent domain used for the single wildcard fallback lookup (RFC C14 /
/// §3.9): drop the leftmost label. `app.acme.example` → `acme.example`. Returns
/// `None` when there is no parent (no dot), so a wildcard lookup is skipped.
#[must_use]
pub fn parent_domain(host: &str) -> Option<String> {
    host.split_once('.')
        .map(|(_, rest)| rest.to_owned())
        .filter(|rest| !rest.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lowercases_and_strips_trailing_dot_and_port() {
        assert_eq!(normalize_host("Acme.Example.COM."), "acme.example.com");
        assert_eq!(normalize_host("acme.example.com:10000"), "acme.example.com");
        assert_eq!(normalize_host("  Acme.Example.com:443 "), "acme.example.com");
    }

    #[test]
    fn ipv6_literal_is_not_truncated_but_port_is_stripped() {
        assert_eq!(normalize_host("[2001:db8::1]:8443"), "2001:db8::1");
        // A bare IPv6 (no port, no brackets) must keep all its colons.
        assert_eq!(normalize_host("2001:db8::1"), "2001:db8::1");
    }

    #[test]
    fn parent_drops_leftmost_label() {
        assert_eq!(parent_domain("app.acme.example"), Some("acme.example".to_owned()));
        assert_eq!(parent_domain("acme.example"), Some("example".to_owned()));
        assert_eq!(parent_domain("example"), None);
    }

    #[test]
    fn normalize_is_idempotent() {
        let once = normalize_host("Shop.Acme.Example.:8080");
        assert_eq!(once, normalize_host(&once));
    }

    #[test]
    fn rejects_control_chars_and_whitespace() {
        // Interior whitespace/control bytes must not survive into a routing key.
        assert_eq!(normalize_host("exa\tmple.com"), "");
        assert_eq!(normalize_host("acme\n.example.com"), "");
        assert_eq!(normalize_host("ex ample.com"), "");
        assert_eq!(normalize_host("nul\0.com"), "");
    }

    #[test]
    fn rejects_non_ascii_unicode_hosts() {
        // Raw Unicode has no single canonical key here — only the encoded
        // A-label (`xn--…`) routes, which passes the LDH check.
        assert_eq!(normalize_host("examplé.com"), "");
        assert_eq!(normalize_host("EXAMPLÉ.com"), "");
        assert_eq!(normalize_host("xn--exampl-gva.com"), "xn--exampl-gva.com");
    }

    #[test]
    fn rejects_empty_labels_and_extra_trailing_dots() {
        assert_eq!(normalize_host(".example.com"), ""); // leading empty label
        assert_eq!(normalize_host("a..b.com"), ""); // interior empty label
        assert_eq!(normalize_host("example.com.."), ""); // 2nd trailing dot → empty label
        assert_eq!(normalize_host("example.com."), "example.com"); // single root dot ok
    }

    #[test]
    fn rejects_userinfo_and_stray_at() {
        // `user:pass@host` and any `@` are not valid hosts.
        assert_eq!(normalize_host("user:pass@host.com"), "");
        assert_eq!(normalize_host("foo@example.com"), "");
    }

    #[test]
    fn ipv6_literal_still_valid() {
        assert_eq!(normalize_host("[2001:db8::1]:8443"), "2001:db8::1");
        assert_eq!(normalize_host("2001:db8::1"), "2001:db8::1");
    }

    /// domain-host-resolution: the resolver derives its two point-read keys from
    /// `normalize`/`parent_domain` — the EXACT key and the SINGLE-LABEL wildcard
    /// parent — and both key off the same canonical form. Pin that derivation so a
    /// refactor of the ordering (exact-first, then one wildcard hop) can't silently
    /// change which two rows a host consults.
    #[test]
    fn resolver_derives_exact_key_then_single_label_wildcard_parent() {
        // A subdomain: the exact key is the whole canonical host, and the sole
        // wildcard fallback is its immediate parent — exactly one label up.
        let key = normalize_host("App.Example.com:443");
        assert_eq!(key, "app.example.com", "exact lookup keys off the canonical host");
        assert_eq!(
            parent_domain(&key),
            Some("example.com".to_owned()),
            "the wildcard fallback is the single-label parent, not a deeper suffix",
        );
        // Depth is single-label only: the parent of `a.b.example.com` is
        // `b.example.com`, NOT `example.com` — a two-label-up wildcard is never
        // derived, so a nested host can only match a wildcard at its own parent.
        assert_eq!(
            parent_domain("a.b.example.com").as_deref(),
            Some("b.example.com"),
            "nesting climbs exactly one label per resolver hop",
        );
    }

    /// domain-host-resolution (fail-closed): a non-conforming host normalizes to
    /// the empty key, which the resolver and the cert-authorization gate both read
    /// as "no match" — neither the exact nor the wildcard lookup ever runs, so no
    /// tenant (and no cert) can be resolved for it.
    #[test]
    fn non_conforming_host_normalizes_to_no_match() {
        for bad in ["", "   ", ".example.com", "a..b.com", "ex ample.com", "examplé.com"] {
            let key = normalize_host(bad);
            assert!(key.is_empty(), "{bad:?} must normalize to the no-match empty key");
            // An empty key has no parent either — the wildcard hop is skipped too.
            assert_eq!(parent_domain(&key), None, "no wildcard fallback for a no-match host");
        }
    }
}
