#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    dead_code
)]

use libc;
pub use libc::FILE;
pub use libc::{sockaddr, timeval};

pub const PCAP_VERSION_MAJOR: u32 = 2;
pub const PCAP_VERSION_MINOR: u32 = 4;
pub const PCAP_ERRBUF_SIZE: u32 = 256;
pub const PCAP_IF_LOOPBACK: u32 = 1;
pub const PCAP_IF_UP: u32 = 2;
pub const PCAP_IF_RUNNING: u32 = 4;
pub const PCAP_ERROR: i32 = -1;
pub const PCAP_ERROR_BREAK: i32 = -2;
pub const PCAP_ERROR_NOT_ACTIVATED: i32 = -3;
pub const PCAP_ERROR_ACTIVATED: i32 = -4;
pub const PCAP_ERROR_NO_SUCH_DEVICE: i32 = -5;
pub const PCAP_ERROR_RFMON_NOTSUP: i32 = -6;
pub const PCAP_ERROR_NOT_RFMON: i32 = -7;
pub const PCAP_ERROR_PERM_DENIED: i32 = -8;
pub const PCAP_ERROR_IFACE_NOT_UP: i32 = -9;
pub const PCAP_ERROR_CANTSET_TSTAMP_TYPE: i32 = -10;
pub const PCAP_ERROR_PROMISC_PERM_DENIED: i32 = -11;
pub const PCAP_ERROR_TSTAMP_PRECISION_NOTSUP: i32 = -12;
pub const PCAP_WARNING: u32 = 1;
pub const PCAP_WARNING_PROMISC_NOTSUP: u32 = 2;
pub const PCAP_WARNING_TSTAMP_TYPE_NOTSUP: u32 = 3;
pub const PCAP_NETMASK_UNKNOWN: u32 = 4294967295;
pub const PCAP_TSTAMP_HOST: u32 = 0;
pub const PCAP_TSTAMP_HOST_LOWPREC: u32 = 1;
pub const PCAP_TSTAMP_HOST_HIPREC: u32 = 2;
pub const PCAP_TSTAMP_ADAPTER: u32 = 3;
pub const PCAP_TSTAMP_ADAPTER_UNSYNCED: u32 = 4;
pub const PCAP_TSTAMP_PRECISION_MICRO: u32 = 0;
pub const PCAP_TSTAMP_PRECISION_NANO: u32 = 1;
pub type u_char = libc::c_uchar;
pub type u_short = libc::c_ushort;
pub type u_int = libc::c_uint;
pub type bpf_int32 = libc::c_int;
pub type bpf_u_int32 = u_int;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct bpf_program {
    pub bf_len: u_int,
    pub bf_insns: *mut bpf_insn,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct bpf_insn {
    pub code: u_short,
    pub jt: u_char,
    pub jf: u_char,
    pub k: bpf_u_int32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct pcap {
    _unused: [u8; 0],
}
pub type pcap_t = pcap;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct pcap_dumper {
    _unused: [u8; 0],
}
pub type pcap_dumper_t = pcap_dumper;
pub type pcap_if_t = pcap_if;
pub type pcap_addr_t = pcap_addr;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct pcap_file_header {
    pub magic: bpf_u_int32,
    pub version_major: u_short,
    pub version_minor: u_short,
    pub thiszone: bpf_int32,
    pub sigfigs: bpf_u_int32,
    pub snaplen: bpf_u_int32,
    pub linktype: bpf_u_int32,
}
#[allow(non_upper_case_globals)]
pub const pcap_direction_t_PCAP_D_INOUT: pcap_direction_t = 0;
#[allow(non_upper_case_globals)]
pub const pcap_direction_t_PCAP_D_IN: pcap_direction_t = 1;
#[allow(non_upper_case_globals)]
pub const pcap_direction_t_PCAP_D_OUT: pcap_direction_t = 2;
pub type pcap_direction_t = u32;
#[repr(C)]
#[allow(non_camel_case_types)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: bpf_u_int32,
    pub len: bpf_u_int32,
    pub comment: [libc::c_char; 256usize],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct pcap_stat {
    pub ps_recv: u_int,
    pub ps_drop: u_int,
    pub ps_ifdrop: u_int,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct pcap_if {
    pub next: *mut pcap_if,
    pub name: *mut libc::c_char,
    pub description: *mut libc::c_char,
    pub addresses: *mut pcap_addr,
    pub flags: bpf_u_int32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub struct pcap_addr {
    pub next: *mut pcap_addr,
    pub addr: *mut sockaddr,
    pub netmask: *mut sockaddr,
    pub broadaddr: *mut sockaddr,
    pub dstaddr: *mut sockaddr,
}
pub type pcap_handler =
    unsafe extern "C" fn(arg1: *mut u_char, arg2: *const pcap_pkthdr, arg3: *const u_char);
extern "C" {
    pub fn pcap_lookupdev(arg1: *mut libc::c_char) -> *mut libc::c_char;
}
extern "C" {
    pub fn pcap_lookupnet(
        arg1: *const libc::c_char,
        arg2: *mut bpf_u_int32,
        arg3: *mut bpf_u_int32,
        arg4: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_create(arg1: *const libc::c_char, arg2: *mut libc::c_char) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_set_snaplen(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_promisc(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_rfmon(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_timeout(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_tstamp_type(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_immediate_mode(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_buffer_size(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_tstamp_precision(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_get_tstamp_precision(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_activate(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_apple_set_exthdr(p: *mut pcap_t, arg1: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_list_tstamp_types(arg1: *mut pcap_t, arg2: *mut *mut libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_free_tstamp_types(arg1: *mut libc::c_int);
}
extern "C" {
    pub fn pcap_tstamp_type_name_to_val(arg1: *const libc::c_char) -> libc::c_int;
}
extern "C" {
    pub fn pcap_tstamp_type_val_to_name(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_tstamp_type_val_to_description(arg1: libc::c_int) -> *const libc::c_char;
}
/*Changed arg5 type to const pointer instead of mut*/
extern "C" {
    pub fn pcap_open_live(
        arg1: *const libc::c_char,
        arg2: libc::c_int,
        arg3: libc::c_int,
        arg4: libc::c_int,
        arg5: *const libc::c_char,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_open_dead(arg1: libc::c_int, arg2: libc::c_int) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_open_dead_with_tstamp_precision(
        arg1: libc::c_int,
        arg2: libc::c_int,
        arg3: u_int,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_open_offline_with_tstamp_precision(
        arg1: *const libc::c_char,
        arg2: u_int,
        arg3: *mut libc::c_char,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_open_offline(arg1: *const libc::c_char, arg2: *mut libc::c_char) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_fopen_offline_with_tstamp_precision(
        arg1: *mut FILE,
        arg2: u_int,
        arg3: *mut libc::c_char,
    ) -> *mut pcap_t;
}
extern "C" {
    pub fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut libc::c_char) -> *mut pcap_t;
}
/*Chnged arg1 to be const and not mut*/
extern "C" {
    pub fn pcap_close(arg1: *const pcap_t);
}
extern "C" {
    pub fn pcap_loop(
        arg1: *mut pcap_t,
        arg2: libc::c_int,
        arg3: pcap_handler,
        arg4: *mut u_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_dispatch(
        arg1: *mut pcap_t,
        arg2: libc::c_int,
        arg3: pcap_handler,
        arg4: *mut u_char,
    ) -> libc::c_int;
}
/*Changed arg1 to not be mutable*/
extern "C" {
    pub fn pcap_next(arg1: *const pcap_t, arg2: *mut pcap_pkthdr) -> *const u_char;
}
extern "C" {
    pub fn pcap_next_ex(
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const u_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_breakloop(arg1: *mut pcap_t);
}
extern "C" {
    pub fn pcap_stats(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> libc::c_int;
}
extern "C" {
    pub fn pcap_setfilter(arg1: *mut pcap_t, arg2: *const bpf_program) -> libc::c_int; //changed program to false
}
extern "C" {
    pub fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_getnonblock(arg1: *mut pcap_t, arg2: *mut libc::c_char) -> libc::c_int;
}
extern "C" {
    pub fn pcap_setnonblock(
        arg1: *mut pcap_t,
        arg2: libc::c_int,
        arg3: *mut libc::c_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_inject(arg1: *mut pcap_t, arg2: *const libc::c_void, arg3: usize) -> libc::c_int;
}
extern "C" {
    pub fn pcap_sendpacket(
        arg1: *mut pcap_t,
        arg2: *const u_char,
        arg3: libc::c_int,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_statustostr(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_strerror(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_geterr(arg1: *mut pcap_t) -> *mut libc::c_char;
}
extern "C" {
    pub fn pcap_perror(arg1: *mut pcap_t, arg2: *const libc::c_char);
}
extern "C" {
    pub fn pcap_compile(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const libc::c_char,
        arg4: libc::c_int,
        arg5: bpf_u_int32,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_compile_nopcap(
        arg1: libc::c_int,
        arg2: libc::c_int,
        arg3: *mut bpf_program,
        arg4: *const libc::c_char,
        arg5: libc::c_int,
        arg6: bpf_u_int32,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_freecode(arg1: *mut bpf_program);
}
extern "C" {
    pub fn pcap_offline_filter(
        arg1: *const bpf_program,
        arg2: *const pcap_pkthdr,
        arg3: *const u_char,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_datalink(arg1: *const pcap_t) -> libc::c_int; //changed to const
}
extern "C" {
    pub fn pcap_datalink_ext(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_list_datalinks(arg1: *mut pcap_t, arg2: *mut *mut libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_set_datalink(arg1: *mut pcap_t, arg2: libc::c_int) -> libc::c_int;
}
extern "C" {
    pub fn pcap_free_datalinks(arg1: *mut libc::c_int);
}
extern "C" {
    pub fn pcap_datalink_name_to_val(arg1: *const libc::c_char) -> libc::c_int;
}
extern "C" {
    pub fn pcap_datalink_val_to_name(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_datalink_val_to_description(arg1: libc::c_int) -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_snapshot(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_is_swapped(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_major_version(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_minor_version(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE;
}
extern "C" {
    pub fn pcap_fileno(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_dump_open(arg1: *mut pcap_t, arg2: *const libc::c_char) -> *mut pcap_dumper_t;
}
extern "C" {
    pub fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t;
}
extern "C" {
    pub fn pcap_dump_open_append(
        arg1: *mut pcap_t,
        arg2: *const libc::c_char,
    ) -> *mut pcap_dumper_t;
}
extern "C" {
    pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE;
}
extern "C" {
    pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> libc::c_long;
}
extern "C" {
    pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_dump_close(arg1: *mut pcap_dumper_t);
}
extern "C" {
    pub fn pcap_dump(arg1: *mut u_char, arg2: *const pcap_pkthdr, arg3: *const u_char);
}
extern "C" {
    pub fn pcap_findalldevs(arg1: *mut *mut pcap_if_t, arg2: *mut libc::c_char) -> libc::c_int;
}
extern "C" {
    pub fn pcap_freealldevs(arg1: *mut pcap_if_t);
}
extern "C" {
    pub fn pcap_lib_version() -> *const libc::c_char;
}
extern "C" {
    pub fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> libc::c_int;
}
extern "C" {
    pub fn pcap_get_selectable_fd_list(
        arg1: *mut pcap_t,
        arg2: *mut *mut libc::c_int,
    ) -> libc::c_int;
}
extern "C" {
    pub fn pcap_free_selectable_fd_list(arg1: *mut libc::c_int);
}
