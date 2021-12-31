#[derive(Debug)]
pub enum Error {
    InvalidLength,
    UnknownAction,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Action {
    EchoRequest,
    EchoResponse,
}

impl Action {
    fn header_fields(self) -> (u8, u8) {
        match self {
            Action::EchoRequest => (8, 0),
            Action::EchoResponse => (0, 0),
        }
    }
}

#[derive(Debug)]
pub struct Packet {
    pub action: Action,
    pub checksum: u16,
    pub rest: [u8; 4],
    pub data: Box<[u8]>,
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
                write!(
                    f,
                    "{} | {:02X} {:02X} {:02x} {:02x}",
                    match self.data.action {
                        Action::EchoRequest => "ECHOREQ",
                        Action::EchoResponse => "ECHOREP",
                    },
                    self.data.data[0],
                    self.data.data[1],
                    self.data.data[2],
                    self.data.data[3]
                )
            }
        }
    }
}

impl Packet {
    pub fn from_buffer(buf: &[u8]) -> Result<Packet, Error> {
        if buf.len() < 8 {
            return Err(Error::InvalidLength);
        }
        return Ok(Packet {
            checksum: ((buf[2] as u16) << 8) + (buf[3] as u16),
            rest: [buf[4], buf[5], buf[6], buf[7]],
            action: match (buf[0], buf[1]) {
                (0, 0) => Action::EchoResponse,
                (8, 0) => Action::EchoRequest,
                _ => {
                    return Err(Error::UnknownAction);
                }
            },
            data: (&buf[8..]).into(),
        });
    }

    pub fn into_buffer(&self, offset_needed: (usize, usize)) -> Vec<u8> {
        let mut out: Vec<u8> = vec![0u8; offset_needed.0 + 8 + self.data.len() + offset_needed.1];
        let slc = &mut out[offset_needed.0..offset_needed.0 + 8 + self.data.len()];
        let (t, c) = self.action.header_fields();

        slc[0] = t;
        slc[1] = c;
        slc[2] = (self.checksum >> 8) as u8;
        slc[3] = self.checksum as u8;
        slc[4] = self.rest[0];
        slc[5] = self.rest[1];
        slc[6] = self.rest[2];
        slc[7] = self.rest[3];
        slc[8..].copy_from_slice(self.data.as_ref());

        out
    }

    pub fn calc_checksum(&mut self) {
        //if looking to send packet - checksum field should be 0
        let (action, code) = self.action.header_fields();
        let mut checksum: u32 = 0;
        checksum += (action as u32) << 8;
        checksum += code as u32;
        checksum += self.checksum as u32;
        checksum += (self.rest[0] as u32) << 8;
        checksum += self.rest[1] as u32;
        checksum += (self.rest[2] as u32) << 8;
        checksum += self.rest[3] as u32;

        let mut calc_even: bool = true;
        for c in self.data.iter() {
            checksum += match calc_even {
                true => (*c as u32) << 8,
                false => *c as u32,
            };
            calc_even = !calc_even;
        }

        checksum = (checksum >> 16) + (checksum & 0x0000FFFF);
        checksum = (checksum >> 16) + (checksum & 0x0000FFFF);

        self.checksum = !(checksum as u16);
    }
}
