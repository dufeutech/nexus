//! Request-context normalization — the routing-plane share of the system-owned,
//! vendor-free request contract (rules §2/§5; RFC §3.8). Sits beside `geo`.
//!
//! A backend should never have to re-parse raw client headers to learn the basics
//! about a requester. The Tenant Router runs first on every request, so it is
//! where we fold a few standards-based signals into a small, trusted, uniform set:
//!
//!   - **Locale** (`x-locale`, `x-lang`) from `Accept-Language` — BCP 47 / RFC 5646
//!     language tags, selected by RFC 9110 quality (`q`) order.
//!   - **Currency** (`x-currency`) — ISO 4217, derived from the resolved country
//!     (ISO 3166-1 alpha-2) so e.g. the checkout pool has it without guessing.
//!   - **Privacy** (`x-privacy-gpc`, `x-privacy-dnt`) — W3C Global Privacy Control
//!     and (legacy) Do-Not-Track, normalized to plain booleans.
//!   - **Device class** (`x-device-type`) — `mobile` / `desktop` / `unknown`.
//!     Authoritative when the browser sends a User-Agent Client Hint
//!     (`Sec-CH-UA-Mobile`, RFC 8942 / UA-CH); a coarse `User-Agent` fallback
//!     otherwise. We emit `unknown` rather than guess — be certain or say so.
//!
//! Every value is re-normalized here (the input transited the network and is
//! untrusted-shaped); a value that fails its rule is dropped, never forwarded. The
//! SOURCE header names are an adapter concern and live in the edge, not here.

/// The complete set of trusted headers `ClientContext::to_headers` can emit. The
/// edge strip list (RFC C3) MUST remove every one of these from client input; the
/// parity test pins that `to_headers` never emits a name outside this set.
pub const TRUSTED_HEADERS: &[&str] = &[
    "x-locale",
    "x-lang",
    "x-currency",
    "x-privacy-gpc",
    "x-privacy-dnt",
    "x-device-type",
];

/// The raw, boundary-extracted inputs the routing plane normalizes. Borrows the
/// source strings; `country` is the already-normalized geo country (ISO 3166-1
/// alpha-2) used to derive currency.
#[derive(Debug, Default, Clone)]
pub struct ClientContext<'a> {
    pub accept_language: Option<&'a str>,
    pub sec_gpc: Option<&'a str>,
    pub dnt: Option<&'a str>,
    pub sec_ch_ua_mobile: Option<&'a str>,
    pub user_agent: Option<&'a str>,
    pub country: Option<&'a str>,
}

impl ClientContext<'_> {
    /// Normalize every present signal onto its trusted header. Pure and
    /// deterministic; emits only well-formed values, in a fixed order.
    pub fn to_headers(&self) -> Vec<(&'static str, String)> {
        let mut out = Vec::new();
        // Locale + language (BCP 47 best match).
        if let Some((locale, lang)) = self.accept_language.and_then(best_locale) {
            out.push(("x-locale", locale));
            out.push(("x-lang", lang));
        }
        // Currency (ISO 4217) from the resolved country.
        if let Some(cur) = self.country.and_then(country_to_currency) {
            out.push(("x-currency", cur.to_string()));
        }
        // Privacy booleans (omitted when the client sent no signal).
        if let Some(b) = self.sec_gpc.and_then(parse_flag) {
            out.push(("x-privacy-gpc", b.to_string()));
        }
        if let Some(b) = self.dnt.and_then(parse_flag) {
            out.push(("x-privacy-dnt", b.to_string()));
        }
        // Device class: emitted always (mobile / desktop / unknown).
        out.push(("x-device-type", device_type(self.sec_ch_ua_mobile, self.user_agent).to_string()));
        out
    }
}

/// Pick the highest-quality language tag from an `Accept-Language` value and
/// normalize it (RFC 9110 `q`-ordering; BCP 47 / RFC 5646 shape). Returns
/// `(locale, lang)` where `locale` is `lang` or `lang-REGION` and `lang` is the
/// primary subtag. `None` if nothing usable (empty, or only `*`).
fn best_locale(raw: &str) -> Option<(String, String)> {
    let mut best: Option<(f32, usize, &str)> = None; // (q, original index, tag)
    for (idx, part) in raw.split(',').enumerate() {
        let mut it = part.split(';');
        let tag = it.next().unwrap_or("").trim();
        if tag.is_empty() || tag == "*" {
            continue;
        }
        // q-value: default 1.0; clamp to [0,1]; q=0 means "not acceptable".
        let q = it
            .find_map(|p| p.trim().strip_prefix("q="))
            .and_then(|v| v.trim().parse::<f32>().ok())
            .unwrap_or(1.0)
            .clamp(0.0, 1.0);
        if q <= 0.0 {
            continue;
        }
        // Highest q wins; on a tie the earlier-listed tag wins (stable).
        let better = match best {
            Some((bq, _, _)) => q > bq,
            None => true,
        };
        if better {
            best = Some((q, idx, tag));
        }
    }
    let tag = best?.2;
    normalize_tag(tag)
}

/// Normalize a single language tag to `lang` / `lang-REGION`: primary subtag
/// lowercased; a 2-letter region subtag uppercased. Rejects malformed tokens.
fn normalize_tag(tag: &str) -> Option<(String, String)> {
    if !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') || tag.len() > 35 {
        return None;
    }
    let mut subs = tag.split('-');
    let lang = subs.next().unwrap_or("");
    if lang.len() < 2 || lang.len() > 3 || !lang.bytes().all(|b| b.is_ascii_alphabetic()) {
        return None;
    }
    let lang = lang.to_ascii_lowercase();
    // First following 2-letter alpha subtag is the region (skip 4-letter scripts).
    let region = subs.find(|s| s.len() == 2 && s.bytes().all(|b| b.is_ascii_alphabetic()));
    let locale = match region {
        Some(r) => format!("{lang}-{}", r.to_ascii_uppercase()),
        None => lang.clone(),
    };
    Some((locale, lang))
}

/// Parse a binary header signal: `"1"` → true, `"0"` → false, anything else
/// (including `Sec-GPC`'s structured `?1`) handled leniently. `None` if absent of
/// meaning, so a missing signal is omitted rather than reported as `false`.
fn parse_flag(raw: &str) -> Option<bool> {
    match raw.trim() {
        "1" | "?1" | "true" => Some(true),
        "0" | "?0" | "false" => Some(false),
        _ => None,
    }
}

/// Classify the requester as `mobile` / `desktop` / `unknown`.
///
/// The User-Agent Client Hint `Sec-CH-UA-Mobile` is **authoritative** — the
/// browser itself reports `?1` (mobile) or `?0` (not). When it is absent (clients
/// that don't support UA-CH), we fall back to a coarse `User-Agent` check and
/// emit `unknown` whenever we cannot be sure — we never guess `desktop`.
fn device_type(sec_ch_ua_mobile: Option<&str>, user_agent: Option<&str>) -> &'static str {
    if let Some(v) = sec_ch_ua_mobile {
        match v.trim() {
            "?1" => return "mobile",
            "?0" => return "desktop",
            _ => {}
        }
    }
    match user_agent {
        Some(ua) => {
            // RFC/convention: mobile browsers carry the "Mobi" token; phones/tablets
            // also identify by platform. These markers are reliable positives.
            let mobile = ["Mobi", "Android", "iPhone", "iPad", "iPod"];
            if mobile.iter().any(|m| ua.contains(m)) {
                "mobile"
            } else if ["Windows NT", "Macintosh", "X11", "CrOS"].iter().any(|d| ua.contains(d)) {
                "desktop"
            } else {
                // Bots, scripts, unknown clients: be honest.
                "unknown"
            }
        }
        None => "unknown",
    }
}

/// Map an ISO 3166-1 alpha-2 country to its primary ISO 4217 currency. A compact
/// starter set covering major economies + the Eurozone; unmapped countries simply
/// omit `x-currency` (honest absence beats a wrong guess). Extend as needed.
fn country_to_currency(country: &str) -> Option<&'static str> {
    // Eurozone members all use EUR.
    const EUR: &[&str] = &[
        "AT", "BE", "HR", "CY", "EE", "FI", "FR", "DE", "GR", "IE", "IT", "LV", "LT", "LU", "MT",
        "NL", "PT", "SK", "SI", "ES",
    ];
    let c = country.to_ascii_uppercase();
    if EUR.contains(&c.as_str()) {
        return Some("EUR");
    }
    Some(match c.as_str() {
        "US" => "USD",
        "GB" => "GBP",
        "JP" => "JPY",
        "CN" => "CNY",
        "CH" => "CHF",
        "CA" => "CAD",
        "AU" => "AUD",
        "NZ" => "NZD",
        "IN" => "INR",
        "BR" => "BRL",
        "MX" => "MXN",
        "SE" => "SEK",
        "NO" => "NOK",
        "DK" => "DKK",
        "PL" => "PLN",
        "RU" => "RUB",
        "ZA" => "ZAR",
        "SG" => "SGD",
        "HK" => "HKD",
        "KR" => "KRW",
        "TR" => "TRY",
        "AE" => "AED",
        "SA" => "SAR",
        "IL" => "ILS",
        "TH" => "THB",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picks_highest_q_language_and_normalizes() {
        let h = ClientContext {
            accept_language: Some("fr-CH, en;q=0.8, de;q=0.9"),
            ..Default::default()
        }
        .to_headers();
        // fr-CH has the implicit q=1.0, so it wins; normalized lang/locale.
        assert!(h.contains(&("x-locale", "fr-CH".to_string())));
        assert!(h.contains(&("x-lang", "fr".to_string())));
    }

    #[test]
    fn language_q_zero_and_wildcard_are_skipped() {
        let (loc, lang) = best_locale("*, en-US;q=0").map_or((String::new(), String::new()), |x| x);
        assert!(loc.is_empty() && lang.is_empty(), "q=0 and * must yield nothing");
        assert_eq!(best_locale("en-US"), Some(("en-US".to_string(), "en".to_string())));
        assert_eq!(best_locale("pt-br"), Some(("pt-BR".to_string(), "pt".to_string())));
    }

    #[test]
    fn currency_from_country_iso4217() {
        let cur = |c: &str| ClientContext { country: Some(c), ..Default::default() }.to_headers();
        assert!(cur("US").contains(&("x-currency", "USD".to_string())));
        assert!(cur("de").contains(&("x-currency", "EUR".to_string()))); // Eurozone, lowercased in
        assert!(cur("JP").contains(&("x-currency", "JPY".to_string())));
        // Unmapped country → no currency header (honest omission).
        assert!(!cur("ZZ").iter().any(|(k, _)| *k == "x-currency"));
    }

    #[test]
    fn privacy_flags_normalize_and_omit_when_absent() {
        let h = ClientContext { sec_gpc: Some("1"), dnt: Some("0"), ..Default::default() }.to_headers();
        assert!(h.contains(&("x-privacy-gpc", "true".to_string())));
        assert!(h.contains(&("x-privacy-dnt", "false".to_string())));
        // No signals → neither privacy header present.
        let none = ClientContext::default().to_headers();
        assert!(!none.iter().any(|(k, _)| k.starts_with("x-privacy")));
    }

    #[test]
    fn device_client_hint_is_authoritative() {
        let dt = |m: Option<&str>, ua: Option<&str>| {
            ClientContext { sec_ch_ua_mobile: m, user_agent: ua, ..Default::default() }
                .to_headers()
                .into_iter()
                .find(|(k, _)| *k == "x-device-type")
                .unwrap()
                .1
        };
        // Client hint wins even if the UA text disagrees.
        assert_eq!(dt(Some("?1"), Some("Mozilla/5.0 (Windows NT 10.0)")), "mobile");
        assert_eq!(dt(Some("?0"), Some("iPhone")), "desktop");
    }

    #[test]
    fn device_user_agent_fallback_is_honest() {
        let dt = |ua: &str| {
            ClientContext { user_agent: Some(ua), ..Default::default() }
                .to_headers()
                .into_iter()
                .find(|(k, _)| *k == "x-device-type")
                .unwrap()
                .1
        };
        assert_eq!(dt("Mozilla/5.0 (Linux; Android 13) Mobile"), "mobile");
        assert_eq!(dt("Mozilla/5.0 (Macintosh; Intel Mac OS X)"), "desktop");
        // A bot / unrecognized client is never guessed.
        assert_eq!(dt("curl/8.4.0"), "unknown");
        // No UA and no client hint → unknown, still emitted.
        assert_eq!(
            ClientContext::default()
                .to_headers()
                .into_iter()
                .find(|(k, _)| *k == "x-device-type")
                .unwrap()
                .1,
            "unknown"
        );
    }

    #[test]
    fn every_emitted_name_is_a_declared_trusted_header() {
        let h = ClientContext {
            accept_language: Some("en-US"),
            sec_gpc: Some("1"),
            dnt: Some("1"),
            sec_ch_ua_mobile: Some("?1"),
            user_agent: Some("x"),
            country: Some("US"),
        }
        .to_headers();
        for (name, _) in &h {
            assert!(TRUSTED_HEADERS.contains(name), "{name} not in TRUSTED_HEADERS");
        }
    }
}
