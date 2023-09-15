use std::fmt::Debug;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use futures::stream::SplitSink;
use futures::{Sink, SinkExt};
use log::debug;
use tokio::time;

pub async fn remove_binding<Key, S, Item>(key: Key, binding: Arc<DashMap<Key, SplitSink<S, Item>>>)
where
    Key: Hash + Eq + Sized + Debug,
    SplitSink<S, Item>: SinkExt<Item> + Sink<Item>,
    <SplitSink<S, Item> as Sink<Item>>::Error: Debug,
{
    time::sleep(Duration::from_secs(60)).await;
    if let Some(mut entry) = binding.remove(&key) {
        entry.1.close().await.expect("Close udp outbound sink failed");
        debug!("Remove udp binding; sender={:?}", key);
    }
}
