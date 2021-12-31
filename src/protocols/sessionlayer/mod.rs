pub mod icmp;
pub mod tcp;
pub mod udp;

#[derive(Debug)]
pub enum Data {
    Tcp(tcp::Segment),
    Icmp(icmp::Packet),
    Udp(udp::Datagram),
    /// This instance is used for protocols that are yet to be implemented, so that their packets can still be constructed.
    UnknownIpProtocol(u8, Box<[u8]>),
}

impl Data {
    pub fn into_buffer(&self, offset_needed: (usize, usize), checksum_offset: u32) -> Vec<u8> {
        match self {
            Data::Tcp(ref s) => s.into_buffer(offset_needed, checksum_offset),
            Data::Udp(ref d) => d.into_buffer(offset_needed, checksum_offset),
            Data::Icmp(ref i) => i.into_buffer(offset_needed),
            _ => vec![0; offset_needed.0 + offset_needed.1],
        }
    }
}
#[derive(Clone, Copy)]
pub enum PrintStyle {
    Normal,
}
pub struct PrintableData<'a> {
    pub style: PrintStyle,
    pub data: &'a Data,
}

impl<'a> std::fmt::Display for PrintableData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.style {
            PrintStyle::Normal => {
                match self.data {
                    &Data::UnknownIpProtocol(proto, ref data) => {
                        write!(f, "Unknown-{} |", proto)?;
                        for e in data.iter() {
                            write!(f, " {:02X}", e)?;
                        }
                        Ok(())
                    }
                    &Data::Tcp(ref s) => {
                        write!(
                            f,
                            "TCP {}",
                            tcp::PrintableData {
                                style: tcp::PrintStyle::Normal,
                                data: s
                            }
                        )
                    }
                    &Data::Icmp(ref p) => write!(
                        f,
                        "ICMP-{}",
                        icmp::PrintableData {
                            style: icmp::PrintStyle::Normal,
                            data: p
                        }
                    ),
                    &Data::Udp(ref d) => write!(
                        f,
                        "UDP {}",
                        udp::PrintableData {
                            style: udp::PrintStyle::Normal,
                            data: d
                        }
                    ),
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Tcp(tcp::Error),
    Icmp(icmp::Error),
    Udp(udp::Error),
}
