use rand::seq::SliceRandom;
use rand::thread_rng;
use std::convert::TryInto;

const UT_BUFFER_SIZE: usize = 160;

pub struct UTConnection {
    index: u32,
    buffer: [u32; UT_BUFFER_SIZE],
}

impl UTConnection {
    pub fn new() -> Self {
        let mut utc = Self {
            index: UT_BUFFER_SIZE.try_into().unwrap(),
            buffer: [0u32; UT_BUFFER_SIZE],
        };

        for i in 0..utc.buffer.len() {
            utc.buffer[i] = i.try_into().unwrap();
        }

        utc
    }

    pub fn next(&mut self) -> u32 {
        let mut rng = thread_rng();
        let shuffle_slot = self.buffer.choose_mut(&mut rng).unwrap();
        let out_index = *shuffle_slot;
        *shuffle_slot = self.index;
        self.index += 1;
        out_index
    }
}
