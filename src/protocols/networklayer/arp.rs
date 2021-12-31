use std::convert::TryInto;

pub enum PrintStyle {
    Normal,
}

/// Contains a (sender, reciever) address pair for different data-link-layer protocols (for example, Ethernet).
#[derive(Debug, Clone, Copy)]
pub enum LLAddressPair {
    Ethernet([u8; 6], [u8; 6]), //(Sender, reciever)
}

impl LLAddressPair {
    fn fmt_sender(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &LLAddressPair::Ethernet(s, _) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                s[0], s[1], s[2], s[3], s[4], s[5]
            ),
        }
    }
    fn fmt_reciever(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &LLAddressPair::Ethernet(_, s) => write!(
                f,
                "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                s[0], s[1], s[2], s[3], s[4], s[5]
            ),
        }
    }
}

/// Contains a (Sender, Reciever) pair for network-layer protocols (for example, IPv4).
#[derive(Debug, Clone, Copy)]
pub enum NLAddressPair {
    Ipv4([u8; 4], [u8; 4]),
    Ipv6([u8; 8], [u8; 8]),
}
impl NLAddressPair {
    fn fmt_sender(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &NLAddressPair::Ipv4(s, _) => write!(f, "{}.{}.{}.{}", s[0], s[1], s[2], s[3]),
            _ => write!(f, "unformatable"),
        }
    }
    fn fmt_reciever(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            &NLAddressPair::Ipv4(_, s) => write!(f, "{}.{}.{}.{}", s[0], s[1], s[2], s[3]),
            _ => write!(f, "unformatable"),
        }
    }
}

#[derive(Debug)]
pub enum Action {
    Request,
    Response,
}

#[derive(Debug)]
pub enum Error {
    InvalidLength,
    InvalidLengthFields,
    UnknownNetworkProtocol,
    UnknownLinkProtocol,
    CantParseNetworkAddress,
    CantParseLinkAddress,
    InvalidOperation,
}

#[derive(Debug)]
pub struct Packet {
    pub hw_addr: LLAddressPair,
    pub sw_addr: NLAddressPair,
    pub action: Action,
}
pub struct PrintableData<'a> {
    pub style: PrintStyle,
    pub data: &'a Packet,
}

impl<'a> std::fmt::Display for PrintableData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.style {
            PrintStyle::Normal => {
                write!(
                    f,
                    "{} (",
                    match self.data.action {
                        Action::Request => "REQ",
                        Action::Response => "REP",
                    }
                )?;
                self.data.hw_addr.fmt_sender(f)?;
                write!(f, ",")?;
                self.data.sw_addr.fmt_sender(f)?;
                write!(f, "->")?;
                match self.data.action {
                    Action::Request => write!(f, "?"),
                    Action::Response => self.data.hw_addr.fmt_reciever(f),
                }?;
                write!(f, ",")?;
                self.data.sw_addr.fmt_reciever(f)?;
                write!(f, ")")
            }
        }
    }
}

impl Packet {
    pub fn from_buffer(raw: &[u8]) -> Result<Packet, Error> {
        let hw_addr: LLAddressPair;
        let sw_addr: NLAddressPair;
        if raw.len() < 6 {
            return Err(Error::InvalidLength);
        }
        let hw_len = raw[4] as usize;
        let sw_len = raw[5] as usize;
        if raw.len() < 8 + 2 * hw_len + 2 * sw_len {
            return Err(Error::InvalidLengthFields);
        }

        hw_addr = match ((raw[0] as u16) << 8) + (raw[1] as u16) {
            1 => LLAddressPair::Ethernet(
                match (&raw[8..8 + hw_len]).try_into() {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::CantParseLinkAddress);
                    }
                },
                match (&raw[8 + hw_len + sw_len..8 + 2 * hw_len + sw_len]).try_into() {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::CantParseLinkAddress);
                    }
                },
            ),
            _ => {
                return Err(Error::UnknownLinkProtocol);
            }
        };

        sw_addr = match ((raw[2] as u16) << 8) + (raw[3] as u16) {
            0x0800 => NLAddressPair::Ipv4(
                match (&raw[8 + hw_len..8 + hw_len + sw_len]).try_into() {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::CantParseNetworkAddress);
                    }
                },
                match (&raw[8 + 2 * hw_len + sw_len..8 + 2 * hw_len + 2 * sw_len]).try_into() {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::CantParseNetworkAddress);
                    }
                },
            ),
            0x86DD => NLAddressPair::Ipv6(
                match (&raw[8 + hw_len..8 + hw_len + sw_len]).try_into() {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::CantParseNetworkAddress);
                    }
                },
                match (&raw[8 + 2 * hw_len + sw_len..8 + 2 * hw_len + 2 * sw_len]).try_into() {
                    Ok(x) => x,
                    Err(_) => {
                        return Err(Error::CantParseNetworkAddress);
                    }
                },
            ),
            _ => {
                return Err(Error::UnknownNetworkProtocol);
            }
        };
        return Ok(Packet {
            hw_addr,
            sw_addr,
            action: match ((raw[6] as u16) << 8) + (raw[7] as u16) {
                1 => Action::Request,
                2 => Action::Response,
                _ => {
                    return Err(Error::InvalidOperation);
                }
            },
        });
    }
    pub fn into_buffer(&self, offset_needed: (usize, usize)) -> Vec<u8> {
        let mut out = vec![0; offset_needed.0 + 28 + offset_needed.1];
        let slc = &mut out[offset_needed.0..offset_needed.0 + 28];
        slc[4] = match self.hw_addr {
            LLAddressPair::Ethernet(_, _) => 6,
        };
        slc[5] = match self.sw_addr {
            NLAddressPair::Ipv4(_, _) => 4,
            NLAddressPair::Ipv6(_, _) => 8,
        };
        let sw_len = slc[5] as usize;
        let hw_len = slc[4] as usize;

        match self.hw_addr {
            LLAddressPair::Ethernet(ref sender_addr, ref reciever_addr) => {
                slc[0] = 0x00;
                slc[1] = 0x01;
                slc[8..8 + hw_len].copy_from_slice(sender_addr);
                slc[8 + hw_len + sw_len..8 + sw_len + 2 * hw_len].copy_from_slice(reciever_addr);
            }
        };

        match self.sw_addr {
            NLAddressPair::Ipv4(ref sender_addr, ref reciever_addr) => {
                slc[2] = 0x08;
                slc[3] = 0x00;
                slc[8 + hw_len..8 + hw_len + sw_len].copy_from_slice(sender_addr);
                slc[8 + 2 * hw_len + sw_len..].copy_from_slice(reciever_addr);
            }
            NLAddressPair::Ipv6(ref sender_addr, ref reciever_addr) => {
                slc[2] = 0x86;
                slc[3] = 0xDD;
                slc[8 + hw_len..8 + hw_len + sw_len].copy_from_slice(sender_addr);
                slc[8 + 2 * hw_len + sw_len..].copy_from_slice(reciever_addr);
            }
        }
        slc[6] = 0;
        slc[5] = match self.action {
            Action::Request => 1,
            Action::Response => 2,
        };

        out
    }
}
