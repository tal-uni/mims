pub const HW_ADDR_LEN: usize = 6;

use super::super::networklayer;

#[derive(Debug)]
pub struct Frame {
    pub dst: [u8; HW_ADDR_LEN],
    pub src: [u8; HW_ADDR_LEN],
    pub next: networklayer::Data,
}

pub enum PrintStyle {
    Normal,
}
pub struct PrintableData<'a> {
    pub style: PrintStyle,
    pub data: &'a Frame,
}

impl<'a> std::fmt::Display for PrintableData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.style {
            PrintStyle::Normal => write!(f, "({:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}->{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}) {}", self.data.src[0], self.data.src[1], self.data.src[2], self.data.src[3], self.data.src[4], self.data.src[5], self.data.dst[0], self.data.dst[1], self.data.dst[2], self.data.dst[3], self.data.dst[4], self.data.dst[5], networklayer::PrintableData{style: networklayer::PrintStyle::Normal, data: &self.data.next})
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidLength,
    UnknownNetworkProtocol,
    NetworkError(networklayer::Error),
}

impl Frame {
    pub fn from_raw_slice(slc: &[u8]) -> Result<Frame, Error> {
        if slc.len() < 2 * HW_ADDR_LEN + 3 {
            return Err(Error::InvalidLength);
        }
        let mut dst = [0; HW_ADDR_LEN];
        let mut src = [0; HW_ADDR_LEN];
        for i in 0..HW_ADDR_LEN {
            dst[i] = slc[i];
            src[i] = slc[i + HW_ADDR_LEN];
        }
        match ((slc[2 * HW_ADDR_LEN] as u16) << 8) + (slc[2 * HW_ADDR_LEN + 1] as u16) {
            //EtherType
            0x0800 => Ok(Frame {
                dst,
                src,
                next: networklayer::Data::Ip(
                    match networklayer::ip::Packet::from_buffer(&slc[2 * HW_ADDR_LEN + 2..]) {
                        Ok(x) => x,
                        Err(e) => (return Err(Error::NetworkError(networklayer::Error::Ip(e)))),
                    },
                ),
            }),
            0x0806 => Ok(Frame {
                dst,
                src,
                next: networklayer::Data::Arp(
                    match networklayer::arp::Packet::from_buffer(&slc[2 * HW_ADDR_LEN + 2..]) {
                        Ok(x) => x,
                        Err(e) => {
                            return Err(Error::NetworkError(networklayer::Error::Arp(e)));
                        }
                    },
                ),
            }),
            _ => Err(Error::UnknownNetworkProtocol),
        }
    }
    pub fn into_buffer(&self, offset_needed: (usize, usize)) -> Vec<u8> {
        let mut vec: Vec<u8> = self
            .next
            .into_buffer((offset_needed.0 + 2 * HW_ADDR_LEN + 2, offset_needed.1));
        if vec.len() < offset_needed.0 + 2 * HW_ADDR_LEN + 2 + offset_needed.1 {
            vec.resize(offset_needed.0 + 2 * HW_ADDR_LEN + 2 + offset_needed.1, 0);
        }
        let slc: &mut [u8] = &mut vec[offset_needed.0..offset_needed.0 + 2 * HW_ADDR_LEN + 2];
        slc[..HW_ADDR_LEN].clone_from_slice(&self.dst);
        slc[HW_ADDR_LEN..2 * HW_ADDR_LEN].clone_from_slice(&self.src);
        match self.next {
            networklayer::Data::Ip(_) => {
                slc[2 * HW_ADDR_LEN] = 0x08;
                slc[2 * HW_ADDR_LEN + 1] = 0x00;
            }
            networklayer::Data::Arp(_) => {
                slc[2 * HW_ADDR_LEN] = 0x08;
                slc[2 * HW_ADDR_LEN + 1] = 0x06;
            }
        }
        vec
    }
}
