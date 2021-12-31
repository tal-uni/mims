#[derive(Debug)]
pub enum Error {
    InvalidLength,
    InvalidLengthField,
}

#[derive(Debug)]
pub struct Datagram {
    src_port: u16,
    dst_port: u16,
    checksum: Option<u16>,
    payload: Box<[u8]>,
}

#[allow(dead_code)]
pub enum PrintStyle {
    Normal,
    Full,
}

pub struct PrintableData<'a> {
    pub style: PrintStyle,
    pub data: &'a Datagram,
}

impl<'a> std::fmt::Display for PrintableData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.style {
            PrintStyle::Normal => {
                write!(f, "({}->{}) |", self.data.src_port, self.data.dst_port)?;
                for e in self.data.payload.as_ref().iter() {
                    write!(f, " {:02X}", e)?;
                }
                Ok(())
            }
            PrintStyle::Full => {
                match self.data.checksum {
                    Some(checksum) => {
                        write!(
                            f,
                            "({}->{},{:04X}) |",
                            self.data.src_port, self.data.dst_port, checksum
                        )?;
                    }
                    None => {
                        write!(
                            f,
                            "({}->{},{}) |",
                            self.data.src_port, self.data.dst_port, "AUTOCHECKSUM"
                        )?;
                    }
                }

                for e in self.data.payload.as_ref().iter() {
                    write!(f, " {:02X}", e)?;
                }
                Ok(())
            }
        }
    }
}

impl Datagram {
    pub fn from_buffer(slc: &[u8]) -> Result<Datagram, Error> {
        if slc.len() < 8 {
            return Err(Error::InvalidLength);
        }
        let l = ((slc[4] as usize) << 8) + (slc[5] as usize);
        if slc.len() < l {
            return Err(Error::InvalidLengthField);
        }
        Ok(Datagram {
            src_port: ((slc[0] as u16) << 8) + (slc[1] as u16),
            dst_port: ((slc[2] as u16) << 8) + (slc[3] as u16),
            checksum: Some(((slc[6] as u16) << 8) + (slc[7] as u16)),
            payload: Box::from(&slc[8..l]),
        })
    }
    pub fn into_buffer(&self, offset_needed: (usize, usize), pseudoheader_sum: u32) -> Vec<u8> {
        let l = 8 + self.payload.len();
        let mut out = vec![0; offset_needed.0 + offset_needed.1 + l];

        let slc = &mut out[offset_needed.0..offset_needed.0 + l];

        slc[0] = (self.src_port >> 8) as u8;
        slc[1] = self.src_port as u8;
        slc[2] = (self.dst_port >> 8) as u8;
        slc[3] = self.dst_port as u8;
        slc[0] = (l >> 8) as u8;
        slc[1] = l as u8;
        match self.checksum {
            Some(x) => {
                slc[6] = (x >> 8) as u8;
                slc[7] = x as u8;
            }
            None => {
                let checksum: u16 = crate::utils::ip_checksum::calc_checksum(
                    slc,
                    pseudoheader_sum + (slc.len() as u32),
                );
                slc[6] = (checksum >> 8) as u8;
                slc[7] = checksum as u8;
            }
        }

        slc[8..].copy_from_slice(self.payload.as_ref());

        out
    }
}
