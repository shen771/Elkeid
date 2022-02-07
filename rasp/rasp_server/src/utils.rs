use std::time::{SystemTime, UNIX_EPOCH};

pub fn four_bytes_to_num(array: [u8; 4]) -> usize {
    let res = ((array[0] as u32) << 24)
        + ((array[1] as u32) << 16)
        + ((array[2] as u32) << 8)
        + ((array[3] as u32) << 0);
    // res.to_usize()
    res as usize
}

// BE
pub fn num_to_four_bytes(len: usize) -> [u8; 4] {
    let x = len as usize;
    let b1: u8 = ((x >> 24) & 0xff) as u8;
    let b2: u8 = ((x >> 16) & 0xff) as u8;
    let b3: u8 = ((x >> 8) & 0xff) as u8;
    let b4: u8 = (x & 0xff) as u8;
    return [b1, b2, b3, b4];
}

pub struct ByteBuf<'a>(pub &'a [u8]);

impl<'a> std::fmt::LowerHex for ByteBuf<'a> {
    fn fmt(&self, fmtr: &mut std::fmt::Formatter) -> Result<(), std::fmt::Error> {
        for byte in self.0 {
            fmtr.write_fmt(format_args!("{:02x}", byte))?;
        }
        Ok(())
    }
}

pub fn generate_timestamp_f64() -> f64 {
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time wen backwards");
    since_the_epoch.as_secs_f64()
}
