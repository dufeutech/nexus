//! DNS adapter for the `OwnershipProof` port (RFC C4 / N2b): resolves the TXT
//! records published under the challenge name so the control plane can match a
//! tenant-published proof against a minted token. The concrete resolver lives
//! here, never in core (rules §2, §5).
//!
//! It queries a PUBLIC recursive resolver, not the host's configured one, so the
//! proof reflects what the tenant published to the world — the same view a
//! certificate authority would take — independent of any internal split-horizon.

use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, CLOUDFLARE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::Resolver;

use router_core::store::BoxError;
use router_core::verify::OwnershipProof;

type TokioResolver = Resolver<TokioRuntimeProvider>;

pub struct DnsOwnershipProof {
    resolver: TokioResolver,
}

impl DnsOwnershipProof {
    /// Resolve against a public recursive resolver (the authoritative public
    /// view of the tenant's DNS).
    ///
    /// # Panics
    /// Panics if the resolver cannot be constructed (a programming/config error
    /// at startup, never a per-request condition).
    #[must_use]
    pub fn public() -> Self {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .build()
        .expect("build public DNS resolver");
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
                    .answers()
                    .iter()
                    .filter_map(|record| {
                        // Keep only TXT answers (a lookup can carry CNAME/SOA etc).
                        let RData::TXT(txt) = &record.data else {
                            return None;
                        };
                        // A TXT record is one-or-more character-strings; join them
                        // into the single logical value the tenant published.
                        Some(
                            txt.txt_data
                                .iter()
                                .map(|b| String::from_utf8_lossy(b))
                                .collect::<String>(),
                        )
                    })
                    .collect();
                Ok(out)
            }
            // "No such record / name" is a found-no-proof (the domain stays
            // pending), NOT a transient failure (RFC C4 port contract).
            Err(e) if e.is_no_records_found() => Ok(Vec::new()),
            Err(e) => Err(Box::new(e)),
        }
    }
}
