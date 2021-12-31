use super::{CaptureMode, Data, CaptureError};
use super::pcap_c;
use super::super::protocols::linklayer;

#[allow(dead_code)]
pub struct CaptureHandle {
    handle: *mut pcap_c::pcap_t,
    mode: CaptureMode,
    snaplen: i32,
    timeout_ms: i32,
    frame_type_code: i32,
}

impl CaptureHandle {
    #[allow(dead_code)]
    pub fn open_live(dev: &str, mode: CaptureMode, timeout_ms: i32, snaplen: i32) -> Result<CaptureHandle, String>{
        let handle: *mut pcap_c::pcap_t;
        if let Ok(err_buf) = std::ffi::CString::new([1; pcap_c::PCAP_ERRBUF_SIZE as usize]) {
            if let Ok(dev_name) = std::ffi::CString::new(dev) {
                unsafe{
                    handle = pcap_c::pcap_open_live(dev_name.as_ptr(), snaplen, match mode {CaptureMode::Promisc => {1}, CaptureMode::NonPromisc => {0}}, timeout_ms, err_buf.as_ptr());
                    match handle.as_mut() {
                        None =>  {
                            match err_buf.into_string() {
                                Err(_) => {return Err(String::from("Could not read error from libcap!"));},
                                Ok(s) => {return Err(s);}
                            }
                        },
                        Some(x) => {
                            return Ok(CaptureHandle{handle: x, mode, snaplen, timeout_ms, frame_type_code: pcap_c::pcap_datalink(handle)});

                        }
                    }

                }
            }else{
                return Err(String::from("Could not read device name as a C string!"));
            }
        }else{
            return Err(String::from("Internal error"));
        }
    }
    #[allow(dead_code)]
    pub fn next(&mut self) -> Result<Data, CaptureError> {
        static mut _RAW_FRAME: pcap_c::pcap_pkthdr = pcap_c::pcap_pkthdr{ts: libc::timeval{tv_sec: 0, tv_usec: 0}, caplen: 0, len: 0, comment: [1; 256]};
        let resp: *const pcap_c::u_char;
        unsafe {
            resp = pcap_c::pcap_next(self.handle, &mut _RAW_FRAME as *mut pcap_c::pcap_pkthdr);
            match resp.as_ref() {
                None => {return Err(CaptureError::CouldNotCapture)},
                Some(_) => {
                    match self.frame_type_code {
                        _ => Ok(Data::LinkLayer(linklayer::Data::Ethernet(
                            match linklayer::ethernet::Frame::from_raw_slice(std::slice::from_raw_parts(resp, _RAW_FRAME.caplen as usize)) {
                                Err(e) => {return Err(CaptureError::LinkLayer(linklayer::Error::Ethernet(e)));},
                                Ok(f) => {f}
                            }
                        )))
                    }
                }
            }
        }
    }
    #[allow(dead_code)]
    pub fn inject(&mut self, to_inject: Data) -> Result<(), ()> {
        let raw_thing = match to_inject {
            Data::LinkLayer(f) => {f.into_buffer((0, 0)).into_boxed_slice()}
        };
        unsafe {
            match pcap_c::pcap_inject(self.handle, raw_thing.as_ptr() as *const libc::c_void, raw_thing.len()) {
                -1 => {Err(())},
                _ => {Ok(())}, //Maybe check that the needed numebr of bytes were written
            }
        }
    }
}


impl<'a> Drop for CaptureHandle {
    fn drop(&mut self) {
        unsafe {
                pcap_c::pcap_close(self.handle);
        }

    }
}
