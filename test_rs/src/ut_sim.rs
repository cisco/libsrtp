use rand::seq::SliceRandom;
use rand::thread_rng;
use std::convert::TryInto;

const UT_BUF: usize = 160;

pub struct UTConnection {
    index: u32,
    buffer: [u32; UT_BUF],
}

impl UTConnection {
    pub fn new() -> Self {
        let mut utc = Self {
            index: UT_BUF.try_into().unwrap(),
            buffer: [0u32; UT_BUF],
        };

        for i in 0..UT_BUF {
            utc.buffer[i] = i.try_into().unwrap();
        }

        let mut rng = thread_rng();
        utc.buffer.shuffle(&mut rng);

        utc
    }

    pub fn next(&mut self) -> u32 {
        let tmp = self.buffer[0];
        self.index += 1;
        self.buffer[0] = self.index;

        let mut rng = thread_rng();
        self.buffer.shuffle(&mut rng);

        tmp
    }
}
