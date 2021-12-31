use crate::control_interfaces::tunnels;

use tokio_stream::{Stream, StreamExt};

pub struct Agent<S, B>
where
    S: Stream,
{
    tunnel_stream: S,
    plain_injection: tokio::sync::mpsc::Sender<B>,
    meta_injection: tokio::sync::mpsc::Sender<B>,
}

pub enum TunnelData<P, M> {
    Plain(P),
    Meta(M),
}

impl<S: Stream<Item = TunnelData<P, M>> + Unpin, P, M, B> Agent<S, B>
where
    P: tunnels::Tunnelable<B>,
    M: tunnels::Tunnelable<B>,
{
    /// While running, the proxy forwards packets between the interfaces so that the tunnel encodes plain information at one end and decodes it at the other end.
    pub async fn run<T>(&mut self, mut tun: T) -> ()
    where
        T: tunnels::Tunnel<P, M, Base = B>,
    {
        while let Some(action) = self.tunnel_stream.next().await {
            let sent = match action {
                TunnelData::Plain(p) => self.meta_injection.send(M::embellish(tun.encode(p))).await,
                TunnelData::Meta(m) => self.plain_injection.send(P::embellish(tun.decode(m))).await,
            };
            match sent {
                Ok(_) => {}
                Err(_) => {
                    break;
                }
            }
        }
    }
}

/// Constructs the proxy.
pub fn new<B, P, M, S1, S2>(
    plain_stream: S1,
    meta_stream: S2,
    plain_injection: tokio::sync::mpsc::Sender<B>,
    meta_injection: tokio::sync::mpsc::Sender<B>,
) -> Agent<impl Stream<Item = TunnelData<P, M>>, B>
where
    P: tunnels::Tunnelable<B>,
    M: tunnels::Tunnelable<B>,
    S1: Stream<Item = B>,
    S2: Stream<Item = B>,
{
    Agent {
        tunnel_stream: StreamExt::merge(
            StreamExt::filter_map(plain_stream, |b| match P::extract(b) {
                None => None,
                Some(p) => Some(TunnelData::<P, M>::Plain(p)),
            }),
            StreamExt::filter_map(meta_stream, |b| match M::extract(b) {
                None => None,
                Some(m) => Some(TunnelData::<P, M>::Meta(m)),
            }),
        ),
        plain_injection,
        meta_injection,
    }
}

/// This method constructs the proxy from a single stream.
#[allow(dead_code)]
pub fn new_unistream<B, P, M, S>(
    tunnel_stream: S,
    plain_injection: tokio::sync::mpsc::Sender<B>,
    meta_injection: tokio::sync::mpsc::Sender<B>,
) -> Agent<impl Stream<Item = TunnelData<P, M>>, B>
where
    P: tunnels::Tunnelable<B>,
    M: tunnels::Tunnelable<B>,
    S: Stream<Item = TunnelData<P, M>>,
{
    Agent {
        tunnel_stream,
        plain_injection,
        meta_injection,
    }
}
