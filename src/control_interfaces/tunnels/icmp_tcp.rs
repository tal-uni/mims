use std::future;

use crate::control_interfaces;
use crate::protocols::{networklayer, sessionlayer};

use tokio_stream::StreamExt;

use serde::Deserialize;

/// A tunneled ICMP packet.
pub struct Icmp {
    /// The segment that was encoded in the tunnel.
    packet: sessionlayer::tcp::Segment,
    /// The ICMP action that the packet contained.
    action: sessionlayer::icmp::Action,
    /// Data from the rest-of-header field of the packet. This field is used to indicate the destination of TCP segments.
    original_dst: [u8; 4],
    /// Metadata about the ICMP packet.
    metadata: control_interfaces::stack::ipv4::Metadata,
}

/// A TCP segment.
pub struct Tcp {
    /// The tcp segment.
    segment: sessionlayer::tcp::Segment,
    /// The segment's metadata.
    metadata: control_interfaces::stack::ipv4::Metadata,
}

impl super::Tunnelable<control_interfaces::pcap::Data> for Icmp {
    fn extract(inp: control_interfaces::pcap::Data) -> Option<Self> {
        match inp {
            control_interfaces::pcap::Data::LinkLayer(l) => {
                match control_interfaces::stack::ipv4::Metadata::extract(l) {
                    Some((sessionlayer::Data::Icmp(p), m)) => {
                        match sessionlayer::tcp::Segment::from_buffer(&p.data.as_ref()) {
                            Ok(s) => Some(Icmp {
                                packet: s,
                                metadata: m,
                                action: p.action,
                                original_dst: p.rest,
                            }),
                            Err(_) => None,
                        }
                    }
                    _ => None,
                }
            }
        }
    }
    fn embellish(self) -> control_interfaces::pcap::Data {
	// When writing a TCP packet to a buffer (and calculating it's checksum), one must take into account the IPv4 pseudoheader.
        let mut pseudo_header = [0; 10];
        pseudo_header[..4].copy_from_slice(&self.metadata.ip_src);
        pseudo_header[4..8].copy_from_slice(&self.metadata.ip_dst);
        pseudo_header[9] = 0x06;
        let out_data = self.packet.into_buffer(
            (0, 0),
            pseudo_header
                .iter()
                .fold((true, 0u32), |(is_even, sum), i| {
                    (
                        !is_even,
                        sum + ((*i as u32)
                            << match is_even {
                                true => 8,
                                false => 0,
                            }),
                    )
                })
                .1,
        );
        let mut out = sessionlayer::icmp::Packet {
            action: self.action,
            checksum: 0,
            rest: self.original_dst,
            data: out_data.into_boxed_slice(),
        };
        out.calc_checksum();

        control_interfaces::pcap::Data::LinkLayer(
            self.metadata.embellish(sessionlayer::Data::Icmp(out)),
        )
    }
}

impl super::Tunnelable<control_interfaces::pcap::Data> for Tcp {
    fn extract(inp: control_interfaces::pcap::Data) -> Option<Self> {
        match inp {
            control_interfaces::pcap::Data::LinkLayer(l) => {
                match control_interfaces::stack::ipv4::Metadata::extract(l) {
                    Some((sessionlayer::Data::Tcp(s), m)) => Some(Tcp {
                        segment: s,
                        metadata: m,
                    }),
                    _ => None,
                }
            }
        }
    }
    fn embellish(self) -> control_interfaces::pcap::Data {
        control_interfaces::pcap::Data::LinkLayer(
            self.metadata
                .embellish(sessionlayer::Data::Tcp(self.segment)),
        )
    }
}

/// Represents an identity on the network.
#[derive(Deserialize)]
pub struct EndpointIdentity {
    /// The IPv4 address of the machine.
    pub ip: [u8; 4],
    /// The MAC address used to route data to the machine.
    pub mac: [u8; 6],
}

/// A proxy's role in the tunnel's operation.
#[derive(Deserialize)]
pub enum Role {
    /// The proxy interacts with the client directly.
    /// In this case, we will store information about the client.
    Aware(EndpointIdentity),
    /// The proxy interacts with the outside world.
    /// In this case, we will store the route that the proxy will use as it's default gateway.
    Unaware { gateway: [u8; 6] },
}

#[derive(Deserialize)]
pub struct Tunnel {
    /// The identity of the other proxy.
    pub other_proxy: EndpointIdentity,
    /// The identity of the proxy as seen from the "clear" interface (the interface that carries TCP).
    pub clear: EndpointIdentity,
    /// The identity of the proxy as seen from the "meta" interface (the interface that carries ICMP).
    pub meta: EndpointIdentity,
    /// The proxy's role.
    pub my_role: Role,
}

impl super::Tunnel<Tcp, Icmp> for Tunnel {
    type Base = control_interfaces::pcap::Data;
    fn decode(&mut self, inp: Icmp) -> Tcp {
        Tcp {
            metadata: control_interfaces::stack::ipv4::Metadata {
                mac_src: self.meta.mac.clone(),
                mac_dst: match &self.my_role {
                    &Role::Aware(ref e) => e.mac.clone(),
                    &Role::Unaware { gateway } => gateway.clone(),
                },
                ip_src: match &self.my_role {
                    &Role::Aware(_) => inp.original_dst.clone(),
                    &Role::Unaware { .. } => self.meta.ip.clone(),
                },
                ip_dst: match &self.my_role {
                    &Role::Aware(ref e) => e.ip.clone(),
                    &Role::Unaware { .. } => inp.original_dst.clone(),
                },
		//Fragmentation is not currently supported.
                mf: false,
                fragment_offset: networklayer::ip::v4::FragmentOffset::Arbitrary(0),
		//The value of the ID field is forwarded through the ICMP packet itself.
                id: inp.metadata.id,
                dscp: 0,
		//The value of the TTL field is forwarded through the ICMP packet itself.
                ttl: inp.metadata.ttl,
                ecn: networklayer::ip::Ecn::NonEcnCapable,
            },
            segment: inp.packet,
        }
    }
    fn encode(&mut self, inp: Tcp) -> Icmp {
        Icmp {
            packet: inp.segment,
            metadata: control_interfaces::stack::ipv4::Metadata {
                mac_src: self.clear.mac.clone(),
                mac_dst: self.other_proxy.mac.clone(),
                ip_src: self.clear.ip.clone(),
                ip_dst: self.other_proxy.ip.clone(),
		//Fragmentation is not currently supported.
                mf: false,
                fragment_offset: networklayer::ip::v4::FragmentOffset::Arbitrary(0),
		//The value of the ID field is forwarded through the ICMP packet itself.
                id: inp.metadata.id,
                dscp: 0,
		//The value of the TTL field is forwarded through the ICMP packet itself.
                ttl: inp.metadata.ttl,
                ecn: networklayer::ip::Ecn::NonEcnCapable,
            },
            action: match &self.my_role {
                &Role::Aware(_) => sessionlayer::icmp::Action::EchoRequest,
                &Role::Unaware { .. } => sessionlayer::icmp::Action::EchoResponse,
            },
            original_dst: match &self.my_role {
                &Role::Aware(_) => inp.metadata.ip_dst,
                &Role::Unaware { .. } => inp.metadata.ip_src,
            },
        }
    }
}

#[derive(std::fmt::Debug)]
pub enum InterfaceError {
    OpenClear,
    OpenInt,
    ApplyFilter,
}

impl Tunnel {
    /// Goes through the process of opening interfaces in the manner required by the tunnel.
    pub fn open_with(
        self,
        clear_iface: &str,
        int_iface: &str,
    ) -> Result<impl future::Future, InterfaceError> {
        let (inject_snd, inject_rcv) =
            control_interfaces::mpsc::Receiver::<control_interfaces::pcap::Data>::new_bounded(100);
        let (aux_snd, aux_rcv) =
            control_interfaces::mpsc::Receiver::<control_interfaces::pcap::Data>::new_bounded(100);

        let mut plain_handle = match control_interfaces::pcap::CaptureHandle::open_live(
            clear_iface,
            control_interfaces::pcap::CaptureMode::Promisc,
            100,
            65535,
        ) {
            Ok(t) => t,
            Err(_) => {
                return Err(InterfaceError::OpenClear);
            }
        };
        match plain_handle.with_filter(
            format!(
                "ip proto \\icmp and dst net {}.{}.{}.{} and src net {}.{}.{}.{} and icmp[icmptype] = {}",
                self.clear.ip[0],
                self.clear.ip[1],
                self.clear.ip[2],
                self.clear.ip[3],
                self.other_proxy.ip[0],
                self.other_proxy.ip[1],
                self.other_proxy.ip[2],
                self.other_proxy.ip[3],
		match &self.my_role {&Role::Aware(_) => "icmp-echoreply", &Role::Unaware{..} => "icmp-echo"}
            )
            .as_str(),
            None,
        ) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("Could not compile or apply filter!");
                return Err(InterfaceError::ApplyFilter);
            }
        }

        let mut meta_handle = match control_interfaces::pcap::CaptureHandle::open_live(
            int_iface,
            control_interfaces::pcap::CaptureMode::Promisc,
            100,
            65535,
        ) {
            Ok(t) => t,
            Err(_) => return Err(InterfaceError::OpenInt),
        };

        match meta_handle.with_filter(
            match self.my_role {
                Role::Unaware { .. } => format!(
                    "ip proto \\tcp and dst net {}.{}.{}.{}",
                    self.meta.ip[0], self.meta.ip[1], self.meta.ip[2], self.meta.ip[3]
                ),
                Role::Aware(EndpointIdentity { ip, .. }) => format!(
                    "ip proto \\tcp and src net {}.{}.{}.{}",
                    ip[0], ip[1], ip[2], ip[3]
                ),
            }
            .as_str(),
            None,
        ) {
            Ok(_) => {}
            Err(_) => {
                eprintln!("Could not compile or apply filter");
                return Err(InterfaceError::ApplyFilter);
            }
        };

        let (main_cloud, packets) =
            control_interfaces::pcap_cloud::Cloud::new(plain_handle, inject_rcv);
        let (clear_cloud, cleartext) =
            control_interfaces::pcap_cloud::Cloud::new(meta_handle, aux_rcv);

        let mut proxy = crate::agents::proxy::new(
            cleartext.filter_map(|r| match r {
                Ok((_, d)) => Some(d),
                _ => None,
            }),
            packets.filter_map(|r| match r {
                Ok((_, d)) => Some(d),
                _ => None,
            }),
            aux_snd,
            inject_snd,
        );

        Ok(async move { tokio::join!(main_cloud.run(), clear_cloud.run(), proxy.run(self)) })
    }
}
