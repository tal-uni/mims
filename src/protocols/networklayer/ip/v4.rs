use super::super::super::sessionlayer;
use std::convert::TryInto;

/// Represents the fragment-offset field in IPv4 (and the DF flag). The implementation stores the contents of the field even in the case that the data is irrelevant so that information in that field can still be accessed.
#[derive(Debug, Clone, Copy)]
pub enum FragmentOffset {
    Meaningfull(u16),
    Arbitrary(u16),
}

#[derive(Debug)]
pub struct Packet {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub id: u16,
    pub ttl: u8,
    /// The field is not an enum as configuration can vary between networks.
    pub dscp: u8,
    pub ecn: super::Ecn,
    pub mf: bool,
    pub fragment_offset: FragmentOffset,
    checksum: Option<u16>,
    pub next: sessionlayer::Data,
}

pub enum PrintStyle {
    Normal,
}
pub struct PrintableData<'a> {
    pub style: PrintStyle,
    pub data: &'a Packet,
}

impl<'a> std::fmt::Display for PrintableData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.style {
            PrintStyle::Normal => write!(
                f,
                "({:04X}:{}.{}.{}.{}->{}.{}.{}.{},TTL-{}{}) {}",
                self.data.id,
                self.data.src[0],
                self.data.src[1],
                self.data.src[2],
                self.data.src[3],
                self.data.dst[0],
                self.data.dst[1],
                self.data.dst[2],
                self.data.dst[3],
                self.data.ttl,
                match self.data.fragment_offset {
                    FragmentOffset::Arbitrary(_) => format!(""),
                    FragmentOffset::Meaningfull(n) => format!(
                        ",FRAG-{}{}",
                        n,
                        match self.data.mf {
                            true => "",
                            false => "-LF",
                        }
                    ),
                },
                sessionlayer::PrintableData {
                    style: sessionlayer::PrintStyle::Normal,
                    data: &self.data.next
                }
            ),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidLength,
    InvalidLengthField,
    CantParseIP,
    SessionErr(sessionlayer::Error),
    InternalEcnErr,
}

impl Packet {
    pub fn from_buffer(slc: &[u8]) -> Result<Packet, Error> {
        if slc.len() < 20 {
            return Err(Error::InvalidLength);
        }
        let tot_size = ((slc[2] as usize) << 8) | (slc[3] as usize);
        let head_size = 4 * ((slc[0] & 0b00001111) as usize);
        if tot_size > slc.len() || head_size > tot_size || head_size < 20 {
            return Err(Error::InvalidLengthField);
        }

        return Ok(Packet {
            src: match (&slc[12..16]).try_into() {
                Err(_) => return Err(Error::CantParseIP),
                Ok(x) => x,
            },
            dst: match (&slc[16..20]).try_into() {
                Err(_) => return Err(Error::CantParseIP),
                Ok(x) => x,
            },
            ttl: slc[8],
            dscp: slc[1] >> 2,
            ecn: match super::Ecn::from_u8(slc[1] & 0x03) {
                Ok(x) => x,
                Err(_) => {
                    return Err(Error::InternalEcnErr);
                }
            },
            id: ((slc[4] as u16) << 8) + (slc[5] as u16),
            mf: match slc[6] & 0b00100000 {
                0 => false,
                _ => true,
            },
            fragment_offset: match slc[6] & 0b01000000 {
                0 => FragmentOffset::Arbitrary((((slc[6] << 3) as u16) << 5) + (slc[7] as u16)),
                _ => FragmentOffset::Meaningfull((((slc[6] << 3) as u16) << 5) + (slc[7] as u16)),
            },
            checksum: Some(((slc[10] as u16) << 8) | (slc[11] as u16)),
            next: match slc[9] {
                //ICMP has protocol number 0x01.
                0x01 => sessionlayer::Data::Icmp(
                    match sessionlayer::icmp::Packet::from_buffer(&slc[head_size..tot_size]) {
                        Ok(x) => x,
                        Err(e) => {
                            return Err(Error::SessionErr(sessionlayer::Error::Icmp(e)));
                        }
                    },
                ),
		//TCP has protocol number 0x06.
                0x06 => sessionlayer::Data::Tcp(
                    match sessionlayer::tcp::Segment::from_buffer(&slc[head_size..tot_size]) {
                        Ok(x) => x,
                        Err(e) => {
                            return Err(Error::SessionErr(sessionlayer::Error::Tcp(e)));
                        }
                    },
                ),
		//UDp has protocol number 0x06.
                0x11 => sessionlayer::Data::Udp(
                    match sessionlayer::udp::Datagram::from_buffer(&slc[head_size..tot_size]) {
                        Ok(x) => x,
                        Err(e) => return Err(Error::SessionErr(sessionlayer::Error::Udp(e))),
                    },
                ),
                c => sessionlayer::Data::UnknownIpProtocol(c, slc[head_size..tot_size].into()),
            },
        });
    }
    pub fn into_buffer(&self, offset_needed: (usize, usize)) -> Vec<u8> {
        let mut pseudo_header = [0u8; 10];
        pseudo_header[..4].copy_from_slice(&self.src);
        pseudo_header[4..8].copy_from_slice(&self.dst);
        pseudo_header[9] = match self.next {
            sessionlayer::Data::Icmp(_) => 0x01,
            sessionlayer::Data::Tcp(_) => 0x06,
            sessionlayer::Data::Udp(_) => 0x11,
            sessionlayer::Data::UnknownIpProtocol(c, _) => c, //Reserved and not used in real ipv4.
        };
        let mut v = self.next.into_buffer(
            (offset_needed.0 + 20, offset_needed.1),
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
        let len = v.len() - offset_needed.0 - offset_needed.1;
        if v.len() < 20 {
            v.resize(20, 0);
        }
        let slc = &mut v[offset_needed.0..offset_needed.0 + 20];
        slc[0] = 0x45;
        slc[1] = (self.dscp << 2) | self.ecn.to_u8();
        slc[2] = ((len as u16) >> 8) as u8;
        slc[3] = len as u8;
        slc[4] = (self.id >> 8) as u8;
        slc[5] = self.id as u8;
        slc[6] = 0 | match self.mf {
            true => 0x20,
            false => 0,
        };
        match self.fragment_offset {
            FragmentOffset::Meaningfull(n) => {
                slc[6] |= (n >> 8) as u8;
                slc[7] = n as u8;
            }
            FragmentOffset::Arbitrary(n) => {
                slc[6] |= 0x40 | ((n >> 8) as u8);
                slc[7] = n as u8;
            }
        }
        slc[8] = self.ttl;
        slc[9] = pseudo_header[9];
        slc[12..16].clone_from_slice(&self.src);
        slc[16..20].clone_from_slice(&self.dst);

        match self.checksum {
            Some(c) => {
                slc[10] = (c >> 8) as u8;
                slc[11] = c as u8;
            }
            None => {
                slc[10] = 0;
                slc[11] = 0;
                let checksum = crate::utils::ip_checksum::calc_checksum(&slc[..20], 0);

                slc[10] = (checksum >> 8) as u8;
                slc[11] = checksum as u8;
            }
        }
        v
    }
}

impl Packet {
    pub fn from_metadata(
        src: [u8; 4],
        dst: [u8; 4],
        id: u16,
        dscp: u8,
        ecn: super::Ecn,
        mf: bool,
        fragment_offset: FragmentOffset,
        ttl: u8,
        next: sessionlayer::Data,
    ) -> Packet {
        Packet {
            src,
            dst,
            id,
            ttl,
            dscp,
            ecn,
            mf,
            fragment_offset,
            checksum: None,
            next,
        }
    }
}
