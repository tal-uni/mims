/// A simple control interface that wraps an [tokio::sync::mpsc](MPSC channel)
pub mod mpsc;
/// The initial control interface that extracts packets from libpcap.
pub mod pcap;
/// An interface that splits a pcap handle into a recieving component and an injection component.
pub mod pcap_cloud;
/// Extracts data from specific protocol stacks.
pub mod stack;
/// Tunnels can encode some protocols within others.
pub mod tunnels;

use tokio_stream::Stream;

pub trait ControlInterface<O>: Stream<Item = O> {}
