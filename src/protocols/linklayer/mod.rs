/// The Ethernet protocol.
pub mod ethernet;

#[derive(Debug)]
pub enum Data {
    Ethernet(ethernet::Frame),
}

impl Data {
    pub fn into_buffer(&self, offset_needed: (usize, usize)) -> Vec<u8> {
        match self {
            Data::Ethernet(f) => f.into_buffer(offset_needed),
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
                &Data::Ethernet(ref frame) => write!(
                    f,
                    "Ethernet {}",
                    ethernet::PrintableData {
                        style: ethernet::PrintStyle::Normal,
                        data: frame
                    }
                ),
            },
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Ethernet(ethernet::Error),
}

impl std::convert::From<ethernet::Error> for Error {
    fn from(thing: ethernet::Error) -> Error {
        Error::Ethernet(thing)
    }
}
