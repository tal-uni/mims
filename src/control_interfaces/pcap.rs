use crate::pcap_c;
use crate::protocols::linklayer;
use libc;

#[cfg(unix)]
use tokio;

#[derive(Debug)]
pub enum Data {
    LinkLayer(linklayer::Data),
}

#[derive(Clone, Copy)]
pub enum PrintStyle {
    Normal,
}
pub struct PrintableData<'a> {
    pub style: PrintStyle,
    pub data: &'a Data,
}

pub struct PrintableDataOwned {
    pub style: PrintStyle,
    pub data: Data,
}

impl<'a> std::fmt::Display for PrintableData<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self.style {
            PrintStyle::Normal => match &self.data {
                &Data::LinkLayer(ref frame) => write!(
                    f,
                    "{}",
                    linklayer::PrintableData {
                        style: linklayer::PrintStyle::Normal,
                        data: frame
                    }
                ),
            },
        }
    }
}

impl std::fmt::Display for PrintableDataOwned {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{}",
            PrintableData {
                style: self.style,
                data: &self.data
            }
        )
    }
}

#[derive(Debug)]
pub enum CaptureError {
    LinkLayer(linklayer::Error),
    CouldNotCapture,
    CouldNotReadSelectableFd,
    CouldNotCaptureAfterFdReady,
}

#[allow(dead_code)]
pub enum CaptureMode {
    NonPromisc,
    Promisc,
}

enum State {
    Idle,
    WaitingForFd,
}

#[allow(dead_code)]
pub struct CaptureHandle {
    /// The action pcap_t that contains the handle.
    handle: std::sync::atomic::AtomicPtr<pcap_c::pcap_t>,
    /// The file descriptor that will be used to perform asynchronous reading from libpcap.
    selectable_fd: tokio::io::unix::AsyncFd<std::os::unix::io::RawFd>,
    /// The current state of the handle. This will be used in order to perform asynchronous reads from libpcap.
    state: State,
    /// The mode at which the handle operates.
    mode: CaptureMode,
    /// the snaplen parameter that has been passed to open_live.
    snaplen: i32,
    /// The timeout parameter that has been passed to open_live.
    timeout_ms: i32,
    /// the frame type that the handle listens for.
    frame_type_code: i32,
}

pub enum FilterErr {
    InvalidFilter,
    CouldNotApply,
}

pub struct Filter {
    bpf_prog: pcap_c::bpf_program,
}

impl CaptureHandle {
    /// This method opens a device using libpcap and registers a selectable file descriptor for asynchronous operations.
    pub fn open_live(
        dev: &str,
        mode: CaptureMode,
        timeout_ms: i32,
        snaplen: i32,
    ) -> Result<CaptureHandle, String> {
        let handle: *mut pcap_c::pcap_t;
        if let Ok(err_buf) = std::ffi::CString::new([1; pcap_c::PCAP_ERRBUF_SIZE as usize]) {
            if let Ok(dev_name) = std::ffi::CString::new(dev) {
                unsafe {
                    handle = pcap_c::pcap_open_live(
                        dev_name.as_ptr(),
                        snaplen,
                        match mode {
                            CaptureMode::Promisc => 1,
                            CaptureMode::NonPromisc => 0,
                        },
                        timeout_ms,
                        err_buf.as_ptr(),
                    );
                    match handle.as_mut() {
                        None => match err_buf.into_string() {
                            Err(_) => {
                                return Err(String::from("Could not read error from libcap!"));
                            }
                            Ok(s) => {
                                return Err(s);
                            }
                        },
                        Some(x) => {
                            match pcap_c::pcap_setnonblock(x, 1, err_buf.as_ptr() as *mut i8) {
                                pcap_c::PCAP_ERROR => {
                                    return Err(match err_buf.into_string() {
                                        Err(_) => String::from("Could not read error from libcap!"),
                                        Ok(s) => s,
                                    })
                                }
                                _ => {
                                    return match pcap_c::pcap_get_selectable_fd(x) {
                                        -1 => Err(String::from("Could not get FD!")),
                                        fd => Ok(CaptureHandle {
                                            handle: std::sync::atomic::AtomicPtr::new(x),
                                            state: State::Idle,
                                            mode,
                                            snaplen,
                                            timeout_ms,
                                            frame_type_code: pcap_c::pcap_datalink(handle),
                                            selectable_fd: match tokio::io::unix::AsyncFd::new(fd) {
                                                Err(_) => {
                                                    return Err(String::from(
                                                        "Could not read selectable fd!",
                                                    ));
                                                }
                                                Ok(s) => s,
                                            },
                                        }),
                                    }
                                }
                            };
                        }
                    }
                }
            } else {
                return Err(String::from("Could not read device name as a C string!"));
            }
        } else {
            return Err(String::from("Internal error"));
        }
    }
    /// Asynchronously reads a packet from libpcap.
    pub async fn next(&mut self) -> Result<(std::time::SystemTime, Data), CaptureError> {
        let mut res: Result<(std::time::SystemTime, Data), CaptureError> =
            Err(CaptureError::CouldNotCapture);
        let handle_ptr: *mut pcap_c::pcap_t = *self.handle.get_mut();
        match unsafe {
            pcap_c::pcap_dispatch(
                handle_ptr,
                1,
                handle_packet_ethernet,
                ((&mut res) as *mut Result<(std::time::SystemTime, Data), CaptureError>) as *mut u8,
            )
        } {
	    //If libpcap returned data immediately, then it can be returned without waiting.
            1 => {
                return res;
            }
            0 => {}
            _ => {
                return Err(CaptureError::CouldNotCapture);
            }
        }

	//The file descriptor indicates when libpcap recieves a packet.
        match self.selectable_fd.readable().await {
            Ok(mut s) => {
		// Clear the file descriptor so that later reads can be performed.
                s.clear_ready();
                match unsafe {
                    pcap_c::pcap_dispatch(
                        handle_ptr,
                        1,
                        handle_packet_ethernet,
			// The user parameter is used in the callback to determine the location of the output.
                        ((&mut res) as *mut Result<(std::time::SystemTime, Data), CaptureError>)
                            as *mut u8,
                    )
                } {
                    1 => {
                        return res;
                    }
		    //This case should not be reached. It indicates that pcap signaled the program that data is available but none has been found.
                    _ => {
                        return Err(CaptureError::CouldNotCaptureAfterFdReady);
                    }
                }
            }
            Err(_) => {
                return Err(CaptureError::CouldNotReadSelectableFd);
            }
        }
    }

    /// Injects a packet using libpcap.
    pub fn inject(&mut self, to_inject: Data) -> Result<(), ()> {
        let raw_thing = match to_inject {
            Data::LinkLayer(f) => f.into_buffer((0, 0)).into_boxed_slice(),
        };
        let handle_ptr: *mut pcap_c::pcap_t = *self.handle.get_mut();
        unsafe {
            match pcap_c::pcap_inject(
                handle_ptr,
                raw_thing.as_ptr() as *const libc::c_void,
                raw_thing.len(),
            ) {
                -1 => Err(()),
                _ => Ok(()), //Maybe check that the needed numebr of bytes were written
            }
        }
    }

    pub fn compile_filter_optimized(
        &mut self,
        code: &str,
        netmask: Option<pcap_c::bpf_u_int32>,
    ) -> Result<Filter, ()> {
        let mut prog: pcap_c::bpf_program = unsafe { std::mem::zeroed() };
        let handle_ptr: *mut pcap_c::pcap_t = *self.handle.get_mut();
        unsafe {
            match pcap_c::pcap_compile(
                handle_ptr,
                &mut prog as *mut pcap_c::bpf_program,
                (match std::ffi::CString::new(code) {
                    Ok(n) => n,
                    Err(_) => {
                        return Err(());
                    }
                })
                .into_raw(),
                1,
                match netmask {
                    None => pcap_c::PCAP_NETMASK_UNKNOWN,
                    Some(n) => n,
                },
            ) {
                0 => {}
                _ => {
                    return Err(());
                }
            }
        }
        return Ok(Filter { bpf_prog: prog });
    }
    pub fn apply_filter(&mut self, filter: Filter) -> Result<(), ()> {
        let handle_ptr: *mut pcap_c::pcap_t = *self.handle.get_mut();
        match unsafe {
            pcap_c::pcap_setfilter(handle_ptr, &filter.bpf_prog as *const pcap_c::bpf_program)
        } {
            0 => Ok(()),
            _ => Err(()),
        }
    }

    /// Applies a filter to a handle.
    pub fn with_filter(
        &mut self,
        code: &str,
        netmask: Option<pcap_c::bpf_u_int32>,
    ) -> Result<(), FilterErr> {
        match self.compile_filter_optimized(code, netmask) {
            Ok(f) => match self.apply_filter(f) {
                Ok(_) => Ok(()),
                Err(_) => Err(FilterErr::CouldNotApply),
            },
            Err(_) => Err(FilterErr::InvalidFilter),
        }
    }
}

use std::pin::Pin;
use std::task::Poll;
use tokio_stream::Stream;

impl Stream for CaptureHandle {
    type Item = Result<(std::time::SystemTime, Data), CaptureError>;

    /// This method is identical in operation to the next function, but it is implemented on the type itself.
    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<Option<Self::Item>> {
        let mut res: Result<(std::time::SystemTime, Data), CaptureError> =
            Err(CaptureError::CouldNotCapture);
        let handle_ptr: *mut pcap_c::pcap_t = *self.handle.get_mut();
        match self.state {
            State::Idle => {
                match unsafe {
                    pcap_c::pcap_dispatch(
                        handle_ptr,
                        1,
                        handle_packet_ethernet,
                        ((&mut res) as *mut Result<(std::time::SystemTime, Data), CaptureError>)
                            as *mut u8,
                    )
                } {
                    1 => {
                        return Poll::Ready(Some(res));
                    }
                    0 => {}
                    _ => {
                        return Poll::Ready(Some(Err(CaptureError::CouldNotCapture)));
                    }
                }
            }
            _ => {}
        }
        match self.selectable_fd.poll_read_ready(cx) {
            Poll::Ready(Ok(mut s)) => {
                s.clear_ready();
                self.state = State::Idle;
                match unsafe {
                    pcap_c::pcap_dispatch(
                        handle_ptr,
                        1,
                        handle_packet_ethernet,
                        ((&mut res) as *mut Result<(std::time::SystemTime, Data), CaptureError>)
                            as *mut u8,
                    )
                } {
                    1 => {
                        return Poll::Ready(Some(res));
                    }
                    _ => {
                        return Poll::Ready(Some(Err(CaptureError::CouldNotCaptureAfterFdReady)));
                    }
                }
            }
            Poll::Ready(Err(_)) => {
                self.state = State::Idle;
                return Poll::Ready(Some(Err(CaptureError::CouldNotReadSelectableFd)));
            }
            Poll::Pending => {
                self.state = State::WaitingForFd;
                return Poll::Pending;
            }
        }
    }
}

impl Drop for CaptureHandle {
    /// Used to automatically close the interface when the handle is no longer used.
    fn drop(&mut self) {
        unsafe {
            pcap_c::pcap_close(*self.handle.get_mut());
        }
    }
}

/// The handle is used to parse data recieved from libpcap and return the sanitized result.
/// The parsing is done immediately instead of copying the packet first, and so there is no need to copy the data and and parse it later.
#[no_mangle]
unsafe extern "C" fn handle_packet_ethernet(
    user: *mut u8,
    raw: *const pcap_c::pcap_pkthdr,
    data: *const u8,
) {
    // The calling method placed the output into the `user` parameter.
    let out = (user as *mut Result<(std::time::SystemTime, Data), CaptureError>)
        .as_mut()
        .expect("Got NULL pointer for output!");
    *out = match raw.as_ref() {
        None => {
            panic!("Got NULL from libpcap!");
        }
        Some(packet) => {
            let dur = std::time::UNIX_EPOCH
                + std::time::Duration::new(
                    packet.ts.tv_sec as u64,
                    (packet.ts.tv_usec * 1000) as u32,
                );
            match linklayer::ethernet::Frame::from_raw_slice(std::slice::from_raw_parts(
                data,
                packet.caplen as usize,
            )) {
                Err(e) => Err(CaptureError::LinkLayer(linklayer::Error::Ethernet(e))),
                Ok(f) => Ok((dur, Data::LinkLayer(linklayer::Data::Ethernet(f)))),
            }
        }
    };
}
