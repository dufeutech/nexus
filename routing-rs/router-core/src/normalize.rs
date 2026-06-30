//! Host normalization (RFC §3.9) and wildcard parent derivation (RFC C14).
//!
//! Pure, total, deterministic functions: the same host always yields the same
//! key, with NO I/O — so the resolver, the control plane, and the tests all
//! agree on "what the cache/store key is."

/// Canonicalize a request host to its store/cache key: lowercased, trailing dot
/// removed, port removed. Total and deterministic (RFC §3.9 invariant).
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
    host.trim_end_matches('.').to_ascii_lowercase()
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
}
