//! DNS adapter for the `OwnershipProof` port (RFC C4 / N2b): resolves the TXT
//! records published under the challenge name so the control plane can match a
//! tenant-published proof against a minted token. The concrete resolver lives
//! here, never in core (rules §2, §5).
//!
//! It queries a PUBLIC recursive resolver, not the host's configured one, so the
//! proof reflects what the tenant published to the world — the same view a
//! certificate authority would take — independent of any internal split-horizon.

use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::error::ResolveErrorKind;
use hickory_resolver::TokioAsyncResolver;

use router_core::store::BoxError;
use router_core::verify::OwnershipProof;

pub struct DnsOwnershipProof {
    resolver: TokioAsyncResolver,
}

impl DnsOwnershipProof {
    /// Resolve against a public recursive resolver (the authoritative public
    /// view of the tenant's DNS).
    pub fn public() -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), ResolverOpts::default());
        Self { resolver }
    }
}

impl Default for DnsOwnershipProof {
    fn default() -> Self {
        Self::public()
    }
}

#[async_trait]
impl OwnershipProof for DnsOwnershipProof {
    async fn txt_records(&self, name: &str) -> Result<Vec<String>, BoxError> {
        match self.resolver.txt_lookup(name).await {
            Ok(lookup) => {
                let out = lookup
                    .iter()
                    .map(|txt| {
                        // A TXT record is one-or-more character-strings; join them
                        // into the single logical value the tenant published.
                        txt.txt_data()
                            .iter()
                            .map(|b| String::from_utf8_lossy(b))
                            .collect::<String>()
                    })
                    .collect();
                Ok(out)
            }
            // "No such record / name" is a found-no-proof (the domain stays
            // pending), NOT a transient failure (RFC C4 port contract).
            Err(e) if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) => Ok(Vec::new()),
            Err(e) => Err(Box::new(e)),
        }
    }
}
