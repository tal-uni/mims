use super::super::super::sessionlayer;

#[derive(Debug)]
pub struct Packet {
    dst: [u8; 16],
    src: [u8; 16],
    flow: u32,
    traffic: u8,
    ttl: u8,
    next: sessionlayer::Data,
}

pub enum PrintStyle {
    Full(sessionlayer::PrintStyle),
}
pub struct PrintableData<'a> {
    pub style: PrintStyle,
    pub data: &'a Packet,
}

impl<'a> std::fmt::Display for PrintableData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.style {
            PrintStyle::Full(s) =>
                write!(f, "({:08X},{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}->{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x},TTL-{}) {}", self.data.flow,
                    self.data.src[0], self.data.src[1], self.data.src[2], self.data.src[3],
                    self.data.src[4], self.data.src[5], self.data.src[6], self.data.src[7],
                    self.data.src[8], self.data.src[9], self.data.src[10], self.data.src[11],
                    self.data.src[12], self.data.src[13],  self.data.src[14],  self.data.src[15],

                    self.data.dst[0], self.data.dst[1], self.data.dst[2], self.data.dst[3],
                    self.data.dst[4], self.data.dst[5], self.data.dst[6], self.data.dst[7],
                    self.data.dst[8], self.data.dst[9], self.data.dst[10], self.data.dst[11],
                    self.data.dst[12], self.data.dst[13],  self.data.dst[14],  self.data.dst[15],

                    self.data.ttl, sessionlayer::PrintableData{style: s, data: &self.data.next}
                )
        }
    }
}

#[derive(Debug)]
pub enum Error {
    UnknownHeaderLength,
    InvalidPayloadLength,
    SessionErr(sessionlayer::Error),
}

impl Packet {
    pub fn from_buffer(buf: &[u8]) -> Result<Packet, Error> {
        if buf.len() < 40 {
            return Err(Error::UnknownHeaderLength);
        }
        let l = ((buf[4] as u16) << 8) | (buf[5] as u16);
        if buf.len() < (40 + l) as usize {
            return Err(Error::InvalidPayloadLength);
        }
        let mut p = unsafe {
            Packet {
                traffic: (buf[0] << 4) | (buf[1] >> 4),
                flow: (((buf[1] & 0x0F) as u32) << 16) | ((buf[2] as u32) << 8) | (buf[3] as u32),
                ttl: buf[7],
                src: std::mem::MaybeUninit::uninit().assume_init(),
                dst: std::mem::MaybeUninit::uninit().assume_init(),
                next: match buf[6] {
		    // ICMP has protocol number 0x01.
                    0x01 => sessionlayer::Data::Icmp(
                        match sessionlayer::icmp::Packet::from_buffer(&buf[40..]) {
                            Ok(x) => x,
                            Err(e) => {
                                return Err(Error::SessionErr(sessionlayer::Error::Icmp(e)));
                            }
                        },
                    ),
		    // TCP has protocol number 0x01.
                    0x06 => sessionlayer::Data::Tcp(match sessionlayer::tcp::Segment::from_buffer(
                        &buf[40..],
                    ) {
                        Ok(x) => x,
                        Err(e) => {
                            return Err(Error::SessionErr(sessionlayer::Error::Tcp(e)));
                        }
                    }),
		    // UDP has protocol number 0x11.
                    0x11 => sessionlayer::Data::Udp(
                        match sessionlayer::udp::Datagram::from_buffer(&buf[40..]) {
                            Ok(x) => x,
                            Err(e) => return Err(Error::SessionErr(sessionlayer::Error::Udp(e))),
                        },
                    ),
                    c => sessionlayer::Data::UnknownIpProtocol(c, buf[40..].into()),
                },
            }
        };
        p.src.copy_from_slice(&buf[8..24]);
        p.dst.copy_from_slice(&buf[24..40]);
        return Ok(p);
    }
    pub fn into_buffer(&self, offset_needed: (usize, usize)) -> Vec<u8> {
        let mut pseudo_header = [0u8; 36];
        let next: u8 = match &self.next {
            &sessionlayer::Data::Icmp(_) => 0x01,
            &sessionlayer::Data::Tcp(_) => 0x06,
            &sessionlayer::Data::Udp(_) => 0x11,
            &sessionlayer::Data::UnknownIpProtocol(x, _) => x,
        };

        pseudo_header[..16].copy_from_slice(&self.src);
        pseudo_header[16..32].copy_from_slice(&self.dst);
        pseudo_header[35] = next;

        let mut out = self.next.into_buffer(
            (offset_needed.0 + 40, offset_needed.1),
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
        let slc = &mut out[offset_needed.0..offset_needed.0 + 40];
        let payload_len = slc.len() - 40;

        slc[0] = self.traffic >> 4;
        slc[1] = (self.traffic << 4) | ((self.flow >> 16) as u8);
        slc[2] = (self.flow >> 8) as u8;
        slc[3] = self.flow as u8;
        slc[4] = (payload_len >> 8) as u8;
        slc[5] = payload_len as u8;
        slc[6] = next;
        slc[7] = self.ttl;

        slc[8..24].copy_from_slice(&self.src);
        slc[24..40].copy_from_slice(&self.dst);

        out
    }
}
