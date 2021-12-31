/// The address resolution protocol implementation.
pub mod arp;
/// The IP protocls (v4 and v6).
pub mod ip;

#[derive(Debug)]
pub enum Data {
    Ip(ip::Packet),
    Arp(arp::Packet),
}

#[derive(Debug)]
pub enum Error {
    Ip(ip::Error),
    Arp(arp::Error),
}

impl Data {
    pub fn into_buffer(&self, offset_needed: (usize, usize)) -> Vec<u8> {
        match self {
            Data::Ip(ref p) => p.into_buffer(offset_needed),
            Data::Arp(ref p) => p.into_buffer(offset_needed),
        }
    }
}

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
            PrintStyle::Normal => match self.data {
                &Data::Ip(ref packet) => write!(
                    f,
                    "IP{}",
                    ip::PrintableData {
                        style: ip::PrintStyle::Normal,
                        data: packet
                    }
                ),
                &Data::Arp(ref packet) => write!(
                    f,
                    "ARP-{}",
                    arp::PrintableData {
                        style: arp::PrintStyle::Normal,
                        data: packet
                    }
                ),
            },
        }
    }
}
