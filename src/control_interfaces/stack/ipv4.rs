use crate::protocols::{linklayer, networklayer, sessionlayer};

/// This structure contains the metadata required to reconstruct an Ethernet IPv4 packet. 
#[derive(Debug)]
pub struct Metadata {
    pub mac_src: [u8; linklayer::ethernet::HW_ADDR_LEN],
    pub mac_dst: [u8; linklayer::ethernet::HW_ADDR_LEN],
    pub ip_src: [u8; 4],
    pub ip_dst: [u8; 4],
    pub mf: bool,
    pub fragment_offset: networklayer::ip::v4::FragmentOffset,
    pub id: u16,
    pub ttl: u8,
    pub dscp: u8,
    pub ecn: networklayer::ip::Ecn,
}

impl Metadata {
    /// Extracts session-layer data and metadata from arbitrary link-layer data (if possible).
    pub fn extract(raw_data: linklayer::Data) -> Option<(sessionlayer::Data, Self)> {
        match raw_data {
            linklayer::Data::Ethernet(linklayer::ethernet::Frame {
                dst: mac_dst,
                src: mac_src,
                next:
                    networklayer::Data::Ip(networklayer::ip::Packet::V4(networklayer::ip::v4::Packet {
                        src: ip_src,
                        dst: ip_dst,
                        id,
                        dscp,
                        ecn,
                        mf,
                        fragment_offset,
                        next: session,
                        ttl,
                        ..
                    })),
                ..
            }) => Some((
                session,
                Metadata {
                    mac_dst,
                    mac_src,
                    ip_src,
                    ip_dst,
                    id,
                    dscp,
                    ecn,
                    mf,
                    fragment_offset,
                    ttl,
                },
            )),
            _ => None,
        }
    }

    /// Embellishes session-layer data and metadata to construct link-layer data.
    pub fn embellish(&self, raw_data: sessionlayer::Data) -> linklayer::Data {
        linklayer::Data::Ethernet(linklayer::ethernet::Frame {
            dst: self.mac_dst,
            src: self.mac_src,
            next: networklayer::Data::Ip(networklayer::ip::Packet::V4(
                networklayer::ip::v4::Packet::from_metadata(
                    self.ip_src,
                    self.ip_dst,
                    self.id,
                    self.dscp,
                    self.ecn,
                    self.mf,
                    self.fragment_offset,
                    self.ttl,
                    raw_data,
                ),
            )),
        })
    }
}
