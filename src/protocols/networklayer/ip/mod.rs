pub mod v4;
pub mod v6;

/// The ECN field is used in both IPv4 and IPv6
#[derive(Debug, Clone, Copy)]
pub enum Ecn {
    NonEcnCapable,
    EcnCapable(bool),
    CongestionEncountered,
}
impl Ecn {
    pub fn from_u8(raw: u8) -> Result<Ecn, ()> {
        match raw {
            0b00 => Ok(Ecn::NonEcnCapable),
            0b01 => Ok(Ecn::EcnCapable(true)),
            0b10 => Ok(Ecn::EcnCapable(false)),
            0b11 => Ok(Ecn::CongestionEncountered),
            _ => Err(()),
        }
    }
    pub fn to_u8(&self) -> u8 {
        match self {
            Ecn::NonEcnCapable => 0b00,
            Ecn::EcnCapable(true) => 0b01,
            Ecn::EcnCapable(false) => 0b10,
            Ecn::CongestionEncountered => 0b11,
        }
    }
}

#[derive(Debug)]
pub enum Packet {
    V4(v4::Packet),
    V6(v6::Packet),
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
            PrintStyle::Normal => {
                match self.data {
                    &Packet::V4(ref packet) => write!(
                        f,
                        "v4 {}",
                        v4::PrintableData {
                            style: v4::PrintStyle::Normal,
                            data: packet
                        }
                    ), //Do for ipv6
                    &Packet::V6(ref packet) => write!(
                        f,
                        "v6 {}",
                        v6::PrintableData {
                            style: v6::PrintStyle::Full(
                                super::super::sessionlayer::PrintStyle::Normal
                            ),
                            data: packet
                        }
                    ),
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidLength,
    UnknownProtocolVersion,
    V4Err(v4::Error),
    V6Err(v6::Error),
}

impl Packet {
    pub fn from_buffer(slc: &[u8]) -> Result<Packet, Error> {
        if slc.len() < 1 {
            return Err(Error::InvalidLength);
        }
        match slc[0] >> 4 {
            4 => match v4::Packet::from_buffer(slc) {
                Err(e) => {
                    return Err(Error::V4Err(e));
                }
                Ok(r) => {
                    return Ok(Packet::V4(r));
                }
            },
            6 => match v6::Packet::from_buffer(slc) {
                Err(e) => {
                    return Err(Error::V6Err(e));
                }
                Ok(r) => {
                    return Ok(Packet::V6(r));
                }
            },
            _ => {
                return Err(Error::UnknownProtocolVersion);
            }
        }
    }
    pub fn into_buffer(&self, offset_needed: (usize, usize)) -> Vec<u8> {
        match self {
            Packet::V4(ref p) => {
                let mut v = p.into_buffer(offset_needed);
                if v.len() <= offset_needed.0 + offset_needed.1 {
                    v = Vec::<u8>::with_capacity(offset_needed.0 + offset_needed.1);
                }
                v[offset_needed.0] = (v[offset_needed.0] & 0x0F) | 0x40; //Add the protocol's version.
                v
            }
            Packet::V6(ref p) => {
                let mut v = p.into_buffer(offset_needed);
                if v.len() <= offset_needed.0 + offset_needed.1 {
                    v = Vec::<u8>::with_capacity(offset_needed.0 + offset_needed.1);
                }
                v[offset_needed.0] = (v[offset_needed.0] & 0x0F) | 0x60; //Add the protocol's version.
                v
            }
        }
    }
}
