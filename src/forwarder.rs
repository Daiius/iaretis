use hickory_resolver::Resolver;
use hickory_resolver::config::{CLOUDFLARE, ResolverConfig};
use hickory_resolver::lookup::Lookup;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_proto::rr::{Name, RecordType};

pub struct Forwarder {
    resolver: Resolver<TokioRuntimeProvider>,
}

impl Forwarder {
    pub fn new() -> Self {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::udp_and_tcp(&CLOUDFLARE),
            TokioRuntimeProvider::default(),
        )
        .build()
        .expect("failed to build resolver");

        Self { resolver }
    }

    pub async fn resolve(&self, name: &Name, record_type: RecordType) -> Result<Lookup, NetError> {
        self.resolver.lookup(name.clone(), record_type).await
    }
}
