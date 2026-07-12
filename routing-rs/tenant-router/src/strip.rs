use std::collections::HashSet;

// --------------------------------------------------------------------------- //
// edge-trusted-header-strip: the authoritative, single-sourced client-header strip.
//
// The tenant-router is the FIRST component every box-bound request crosses, so the
// load-bearing anti-forgery control lives here (design D2). We DEFAULT-DROP the whole
// nexus-authored "trusted family" by PREFIX from client input and forward only an
// explicit allowlist of permitted hints. Completeness is by prefix, so a newly added
// trusted header a box reads is safe-by-default (dropped) instead of
// forgeable-until-someone-adds-it-to-a-denylist. The edge Envoy + identity sidecar
// denylists are retained only as COARSE defense-in-depth, no longer the primary control.
//
// Single source of truth: this prefix/exact/allowlist set lives ONCE, here, and is
// referenced — never copy-pasted across the mirrored envoy configmaps.
// --------------------------------------------------------------------------- //

/// Lowercased name prefixes of the nexus-authored trusted family. Any client-supplied
/// header whose lowercased name starts with one of these is dropped (unless allowlisted).
/// `x-route` covers both `x-route-pool` and `x-routed-by`.
const TRUSTED_HEADER_PREFIXES: &[&str] = &[
    "x-user-",
    "x-workspace-",
    "x-geo-",
    "x-identity-",
    "x-auth-",
    "x-route",
    "x-enriched-",
    "x-privacy-",
];

/// Exact lowercased trusted-family names that don't share a common prefix with the set
/// above — the normalized request-context annotations nexus authors.
const TRUSTED_HEADER_EXACT: &[&str] = &["x-locale", "x-lang", "x-currency", "x-device-type"];

/// The ONLY client-supplied trusted-family headers the edge forwards — an explicit
/// allowlist of hints a client is permitted to set. A name here is exempt from the
/// default-drop even if it matches a trusted prefix. Kept deliberately tiny.
const CLIENT_HINT_ALLOWLIST: &[&str] = &["x-requested-workspace"];

/// Whether a (lowercased) header name belongs to the nexus-authored trusted family.
pub(crate) fn is_trusted_family(lower_name: &str) -> bool {
    TRUSTED_HEADER_PREFIXES.iter().any(|p| lower_name.starts_with(p))
        || TRUSTED_HEADER_EXACT.contains(&lower_name)
}

/// Compute the client-supplied trusted-family headers to DEFAULT-DROP. `incoming` is the
/// request's header names as received; `authored` is the lowercased set of names THIS
/// filter authors on this path — those are overwritten authoritatively via `set_headers`,
/// so they are EXCLUDED from the remove list to keep the result independent of Envoy's
/// set-vs-remove apply order (a name in both lists could otherwise be wiped after we set
/// it). Returns the original-cased names to remove, de-duplicated.
pub(crate) fn trusted_family_strip(incoming: &[&str], authored: &HashSet<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut remove = Vec::new();
    for &name in incoming {
        let lower = name.to_ascii_lowercase();
        if is_trusted_family(&lower)
            && !CLIENT_HINT_ALLOWLIST.contains(&lower.as_str())
            && !authored.contains(&lower)
            && seen.insert(lower)
        {
            remove.push(name.to_owned());
        }
    }
    remove
}

#[cfg(test)]
mod tests {
    use super::*;

    // ----------------------------------------------------------------------- //
    // edge-trusted-header-strip: the authoritative default-drop-by-prefix control.
    // ----------------------------------------------------------------------- //

    /// The trusted family is recognized by PREFIX (so an un-enumerated member is caught)
    /// and by the few exact context names; nothing outside the family is claimed.
    #[test]
    fn trusted_family_membership_is_by_prefix_and_exact_name() {
        // Enumerated AND un-enumerated members of a trusted prefix are both in-family.
        for h in [
            "x-user-suspended",
            "x-user-entitlements",
            "x-user-roles",
            "x-user-some-future-header", // nobody enumerated this — still caught
            "x-workspace-id",
            "x-geo-country",
            "x-identity-contract",
            "x-auth-required",
            "x-route-pool",
            "x-routed-by",
            "x-enriched-by",
            "x-privacy-gpc",
            "x-locale",
            "x-currency",
            "x-device-type",
        ] {
            assert!(is_trusted_family(h), "{h} must be recognized as trusted-family");
        }
        // Ordinary client/request headers and the permitted hint are NOT in-family.
        for h in ["authorization", "x-api-key", "host", "cf-ray", "accept-language", "x-request-id"] {
            assert!(!is_trusted_family(h), "{h} must NOT be treated as trusted-family");
        }
    }

    /// The core anti-forgery property: an un-enumerated client `x-user-*` is dropped by
    /// DEFAULT, the allowlisted hint survives, ordinary headers are untouched, and a name
    /// this filter authors is NOT put on the remove list (it's overwritten authoritatively).
    #[test]
    fn strip_drops_unknown_trusted_family_keeps_allowlist_and_authored() {
        // What THIS filter authors on the request path (excluded from removal).
        let authored: HashSet<String> =
            ["x-workspace-id", "x-route-pool", "x-routed-by", "x-geo-country"]
                .into_iter()
                .map(str::to_owned)
                .collect();
        let incoming = [
            "x-user-suspended",          // forged revocation signal -> DROP
            "x-user-brand-new",          // un-enumerated trusted header -> DROP by default
            "X-Identity-Contract",       // forged signed-contract copy (mixed case) -> DROP
            "x-requested-workspace",     // allowlisted client hint -> KEEP
            "authorization",             // ordinary header -> KEEP
            "x-workspace-id",            // authored here -> KEEP (overwritten, not removed)
            "x-geo-country",             // authored here -> KEEP
        ];
        let removed = trusted_family_strip(&incoming, &authored);

        assert!(removed.contains(&"x-user-suspended".to_owned()), "a forged revocation header is dropped");
        assert!(removed.contains(&"x-user-brand-new".to_owned()), "an un-enumerated trusted header is dropped by default");
        // Original casing is preserved in the removal name.
        assert!(removed.contains(&"X-Identity-Contract".to_owned()), "a forged contract copy is dropped (case-insensitive match)");
        // Survivors: the allowlisted hint, ordinary headers, and authored names.
        for keep in ["x-requested-workspace", "authorization", "x-workspace-id", "x-geo-country"] {
            assert!(!removed.contains(&keep.to_owned()), "{keep} must survive the strip");
        }
    }
}
