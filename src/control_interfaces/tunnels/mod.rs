/// A TCP over ICMP tunnel.
pub mod icmp_tcp;

pub trait Tunnelable<B>
where
    Self: Sized,
{
    fn extract(base: B) -> Option<Self>;
    fn embellish(self) -> B;
}

pub trait Tunnel<P, M>
where
    P: Tunnelable<Self::Base>,
    M: Tunnelable<Self::Base>,
{
    type Base;
    fn encode(&mut self, p: P) -> M;
    fn decode(&mut self, m: M) -> P;
}
