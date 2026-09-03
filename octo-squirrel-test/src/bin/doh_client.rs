use hickory_resolver::Resolver;
use hickory_resolver::config::CLOUDFLARE;
use hickory_resolver::config::ResolverConfig;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RecordType;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    const NAME: &str = "example.com.";
    let resolver = Resolver::builder_with_config(ResolverConfig::https(&CLOUDFLARE), TokioRuntimeProvider::default()).build()?;
    let result = resolver.lookup(NAME, RecordType::A).await?;
    println!("{:?}", result);
    Ok(())
}
