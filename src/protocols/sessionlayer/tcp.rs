use std::boxed::Box;

#[derive(Debug)]
pub enum Ack {
    Used(u32),
    /// In order to correctly reconstruct the packet accurately, the ack number is stored even if it is meaningless.
    NotPresent(u32),
}

#[derive(Debug)]
pub enum Urgent {
    MeaningfullIndex(u16),
    Arbitrary(u16),
}

#[derive(Debug)]
pub struct Segment {
    src_port: u16,
    dst_port: u16,
    seq_no: u32,
    ack_no: Ack,
    window_size: u16,
    pub checksum: u16,
    urgent_data: Urgent,
    payload: Box<[u8]>,
    syn: bool,
    ns: bool,
    cwr: bool,
    ece: bool,
    psh: bool,
    rst: bool,
    fin: bool,
    options: Box<[u8]>,
}

pub enum PrintStyle {
    Normal,
}
pub struct PrintableData<'a> {
    pub style: PrintStyle,
    pub data: &'a Segment,
}

impl<'a> std::fmt::Display for PrintableData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.style {
            PrintStyle::Normal => {
                write!(
                    f,
                    "({}:{}->{}{})",
                    self.data.seq_no,
                    self.data.src_port,
                    self.data.dst_port,
                    match (self.data.syn, self.data.rst, self.data.fin) {
                        (false, false, false) => "",
                        (true, _, _) => ",SYN",
                        (_, _, true) => ",FIN",
                        (_, true, _) => ",RST",
                    }
                )?;
                write!(f, " |")?;
                for e in self.data.payload.as_ref().iter() {
                    write!(f, " {:02X}", e)?;
                }
                Ok(())
            }
        }
    }
}

#[derive(Debug)]
pub enum Error {
    InvalidLength,
    InvalidLengthField,
}

impl Segment {
    pub fn from_buffer(slc: &[u8]) -> Result<Segment, Error> {
        if slc.len() < 20 {
            return Err(Error::InvalidLength);
        }
        let head_size = 4 * ((slc[12] >> 4) as usize);
        if head_size > slc.len() || head_size < 20 {
            return Err(Error::InvalidLengthField);
        }
        let urg = ((slc[18] as u16) << 8) + (slc[19] as u16);
        return Ok(Segment {
            src_port: ((slc[0] as u16) << 8) | (slc[1] as u16),
            dst_port: ((slc[2] as u16) << 8) | (slc[3] as u16),
            seq_no: ((slc[4] as u32) << 24)
                | ((slc[5] as u32) << 16)
                | ((slc[6] as u32) << 8)
                | (slc[7] as u32),
            ack_no: match slc[13] & 0b00010000 {
                0 => Ack::NotPresent(
                    ((slc[8] as u32) << 24)
                        | ((slc[9] as u32) << 16)
                        | ((slc[10] as u32) << 8)
                        | (slc[11] as u32),
                ),
                _ => Ack::Used(
                    ((slc[8] as u32) << 24)
                        | ((slc[9] as u32) << 16)
                        | ((slc[10] as u32) << 8)
                        | (slc[11] as u32),
                ),
            },
            window_size: ((slc[14] as u16) << 8) | (slc[15] as u16),
            ns: match slc[12] & 0b00000001 {
                0 => false,
                _ => true,
            },
            cwr: match slc[13] & 0b10000000 {
                0 => false,
                _ => true,
            },
            ece: match slc[13] & 0b01000000 {
                0 => false,
                _ => true,
            },
            psh: match slc[13] & 0b00001000 {
                0 => false,
                _ => true,
            },
            rst: match slc[13] & 0b00000100 {
                0 => false,
                _ => true,
            },
            syn: match slc[13] & 0b00000010 {
                0 => false,
                _ => true,
            },
            fin: match slc[13] & 0b00000001 {
                0 => false,
                _ => true,
            },
            urgent_data: match slc[13] & 0b00100000 {
                0 => Urgent::Arbitrary(urg),
                _ => Urgent::MeaningfullIndex(urg),
            },
            checksum: (((slc[16] as u16) << 8) | (slc[17] as u16)),
            options: Box::<[u8]>::from(&slc[20..head_size]),
            payload: Box::<[u8]>::from(&slc[head_size..]),
        });
    }
    pub fn into_buffer(&self, offset_needed: (usize, usize), pseoudo_header_sum: u32) -> Vec<u8> {
        let boundry = offset_needed.0 + 20 + self.payload.len() + self.options.len();
        let mut out = vec![0; boundry + offset_needed.1]; //Adjust for options
        let slc = &mut out[offset_needed.0..boundry];

        slc[0] = (self.src_port >> 8) as u8;
        slc[1] = self.src_port as u8;
        slc[2] = (self.dst_port >> 8) as u8;
        slc[3] = self.dst_port as u8;
        slc[4] = (self.seq_no >> 24) as u8;
        slc[5] = (self.seq_no >> 16) as u8;
        slc[6] = (self.seq_no >> 8) as u8;
        slc[7] = self.seq_no as u8;
        let ack_no = match self.ack_no {
            Ack::Used(n) => n,
            Ack::NotPresent(n) => n,
        };
        slc[8] = (ack_no >> 24) as u8;
        slc[9] = (ack_no >> 16) as u8;
        slc[10] = (ack_no >> 8) as u8;
        slc[11] = ack_no as u8;
        slc[12] = ((5+((self.options.len()/4) as u8)) << 4)
            + 0 // reserved
            + match self.ns {
                true => 1,
                false => 0,
            };
        slc[13] = match self.cwr {
            true => 0x80,
            false => 0,
        } | match self.ece {
            true => 0x40,
            false => 0,
        } | match self.urgent_data {
            Urgent::MeaningfullIndex(_) => 0x20,
            _ => 0,
        } | match self.ack_no {
            Ack::Used(_) => 0x10,
            _ => 0,
        } | match self.psh {
            true => 0x8,
            false => 0,
        } | match self.rst {
            true => 0x4,
            false => 0,
        } | match self.syn {
            true => 0x2,
            false => 0,
        } | match self.fin {
            true => 0x1,
            false => 0,
        };
        slc[14] = (self.window_size >> 8) as u8;
        slc[15] = self.window_size as u8;
        slc[16] = 0;
        slc[17] = 0;
        let urg = match self.urgent_data {
            Urgent::Arbitrary(n) => n,
            Urgent::MeaningfullIndex(n) => n,
        };
        slc[18] = (urg >> 8) as u8;
        slc[19] = urg as u8;
        slc[20..20 + self.options.len()].copy_from_slice(self.options.as_ref());
        slc[20 + self.options.len()..].copy_from_slice(self.payload.as_ref());
        let cs =
            crate::utils::ip_checksum::calc_checksum(slc, pseoudo_header_sum + (slc.len() as u32));
        slc[16] = (cs >> 8) as u8;
        slc[17] = cs as u8;
        out
    }
}
