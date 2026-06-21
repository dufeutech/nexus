//! Plan → domain-count limit (RFC C5) — pure domain logic for the declare quota
//! gate (RFC C3). The mapping is DATA-DRIVEN: this module holds only the value
//! types and the decision, never the concrete limits — the service loads those
//! from configuration and constructs a [`PlanLimits`] (rules §1.3, §5: no embedded
//! constants in logic). Vendor-free (rules §2).

use std::collections::BTreeMap;

/// The maximum number of domains a plan permits, as a domain value: a finite cap
/// or explicitly unbounded (the top tier).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomainLimit {
    Finite(u32),
    Unbounded,
}

/// The structured outcome a declare MUST return when the tenant is already at or
/// above its plan limit (RFC C3): enough for the caller to render an upgrade
/// prompt. `limit` is the finite cap that was hit (an unbounded plan never
/// produces this).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuotaExceeded {
    pub plan: String,
    pub limit: u32,
    pub used: u32,
}

/// The data-driven plan → limit table (RFC C5). Built by the service from
/// configuration; the quota check reads its limit from here, never from a
/// constant.
#[derive(Debug, Clone, Default)]
pub struct PlanLimits {
    limits: BTreeMap<String, DomainLimit>,
}

impl PlanLimits {
    pub fn new(limits: BTreeMap<String, DomainLimit>) -> Self {
        Self { limits }
    }

    /// The most restrictive *configured* limit — the smallest finite cap present.
    /// Falls back to `Finite(0)` when nothing finite is configured, so an unknown
    /// plan is never treated as unbounded (RFC C5: conservative default).
    pub fn most_restrictive(&self) -> DomainLimit {
        self.limits
            .values()
            .filter_map(|l| match l {
                DomainLimit::Finite(n) => Some(*n),
                DomainLimit::Unbounded => None,
            })
            .min()
            .map(DomainLimit::Finite)
            .unwrap_or(DomainLimit::Finite(0))
    }

    /// The limit for a plan. An absent plan resolves to [`Self::most_restrictive`]
    /// — never unbounded (RFC C5).
    pub fn limit_for(&self, plan: &str) -> DomainLimit {
        self.limits
            .get(plan)
            .copied()
            .unwrap_or_else(|| self.most_restrictive())
    }

    /// The quota gate (RFC C3): `Ok` if a tenant on `plan` already holding `used`
    /// domains may declare one more; `Err(QuotaExceeded)` otherwise. The check is
    /// "at or above" — at exactly the limit a further declare is refused.
    pub fn check(&self, plan: &str, used: u32) -> Result<(), QuotaExceeded> {
        match self.limit_for(plan) {
            DomainLimit::Unbounded => Ok(()),
            DomainLimit::Finite(limit) => {
                if used >= limit {
                    Err(QuotaExceeded {
                        plan: plan.to_string(),
                        limit,
                        used,
                    })
                } else {
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PlanLimits {
        let mut m = BTreeMap::new();
        m.insert("free".into(), DomainLimit::Finite(1));
        m.insert("pro".into(), DomainLimit::Finite(10));
        m.insert("enterprise".into(), DomainLimit::Unbounded);
        PlanLimits::new(m)
    }

    #[test]
    fn finite_plan_gates_at_limit() {
        let p = sample();
        assert!(p.check("free", 0).is_ok());
        assert!(p.check("free", 1).is_err()); // at the limit -> refused
        assert_eq!(
            p.check("free", 1).unwrap_err(),
            QuotaExceeded { plan: "free".into(), limit: 1, used: 1 }
        );
        assert!(p.check("pro", 9).is_ok());
        assert!(p.check("pro", 10).is_err());
    }

    #[test]
    fn unbounded_plan_never_exceeds() {
        let p = sample();
        assert!(p.check("enterprise", 1_000_000).is_ok());
    }

    #[test]
    fn unknown_plan_is_most_restrictive_not_unbounded() {
        let p = sample();
        // smallest finite configured is 1 (free); an unknown plan inherits it.
        assert_eq!(p.limit_for("mystery"), DomainLimit::Finite(1));
        assert!(p.check("mystery", 1).is_err());
    }

    #[test]
    fn empty_config_denies_all() {
        let p = PlanLimits::default();
        assert_eq!(p.most_restrictive(), DomainLimit::Finite(0));
        assert!(p.check("anything", 0).is_err());
    }
}
