use hickory_resolver::Resolver;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::lookup::Lookup;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_proto::rr::{Name, RecordType};

pub struct Forwarder {
    resolver: Resolver<TokioConnectionProvider>,
}

impl Forwarder {
    pub fn new() -> Self {
        let resolver = Resolver::builder_with_config(
            ResolverConfig::cloudflare(),
            TokioConnectionProvider::default(),
        )
        .build();

        Self { resolver }
    }

    pub async fn resolve(&self, name: &Name, record_type: RecordType) -> Result<Lookup, hickory_resolver::ResolveError> {
        self.resolver.lookup(name.clone(), record_type).await
    }
}
