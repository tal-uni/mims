pub fn calc_checksum(slc: &[u8], offset: u32) -> u16 {
    let mut checksum: u32 = slc
        .iter()
        .fold((true, 0), |(is_even, sum), val| match is_even {
            true => (false, sum + ((*val as u32) << 8)),
            false => (true, sum + (*val as u32)),
        })
        .1
        + offset;
    checksum = (checksum >> 16) + (checksum & 0x0000FFFF);
    checksum = (checksum >> 16) + (checksum & 0x0000FFFF);

    !(checksum as u16)
}
