use crate::include::rdb::*;
use crate::ut_sim::UTConnection;
use rand::{thread_rng, Rng};
use std::convert::TryInto;
use std::os::raw::c_int;
use std::time::Instant;

const VALIDATION_TRIALS: usize = 1 << 12;
const TIMING_TRIALS: usize = 10_000_000;

#[no_mangle]
extern "C" fn replay_driver_main() -> c_int {
    println!("testing anti-replay database (srtp_rdb_t)...\n");
    if test_rdb_db(VALIDATION_TRIALS).is_err() {
        println!("failed");
        return 1;
    }
    println!("done");

    let rate = rdb_check_adds_per_second(TIMING_TRIALS);
    println!("rdb_check/rdb_adds per second: {:e}", rate);
    0
}

fn rdb_check_add(rdb: &mut ReplayDB, idx: usize) -> Result<(), Error> {
    let idx: u32 = idx.try_into().unwrap();
    if rdb.check(idx).is_err() {
        println!("rdb_check failed at index {}", idx);
        return Err(Error::Fail);
    }

    if rdb.add(idx).is_err() {
        println!("rdb_add_index failed at index {}", idx);
        return Err(Error::Fail);
    }

    Ok(())
}

fn rdb_check_expect_failure(rdb: &ReplayDB, idx: usize) -> Result<(), Error> {
    let idx: u32 = idx.try_into().unwrap();
    match rdb.check(idx) {
        Err(Error::ReplayOld) => Ok(()),
        Err(Error::ReplayFail) => Ok(()),
        _ => {
            println!("rdb_check failed at index {} (false positive)", idx);
            return Err(Error::Fail);
        }
    }
}

fn rdb_check_add_unordered(rdb: &mut ReplayDB, idx: usize) -> Result<(), Error> {
    let idx: u32 = idx.try_into().unwrap();

    match rdb.check(idx) {
        Ok(_) => {}
        Err(Error::ReplayOld) => return Ok(()),
        _ => {
            println!("rdb_check_add_unordered failed at index {}", idx);
            return Err(Error::AlgoFail);
        }
    }

    if rdb.add(idx).is_err() {
        println!("rdb_add_index failed at index {}", idx);
        return Err(Error::AlgoFail);
    }

    Ok(())
}

fn test_rdb_sequential(num_trials: usize) -> Result<(), Error> {
    let mut rdb = ReplayDB::new().unwrap();

    for idx in 0..num_trials {
        rdb_check_add(&mut rdb, idx)?;
        rdb_check_expect_failure(&rdb, idx)?;
    }

    Ok(())
}

fn test_rdb_non_sequential(num_trials: usize) -> Result<(), Error> {
    let mut rdb = ReplayDB::new().unwrap();
    let mut utc = UTConnection::new();

    for _ in 0..num_trials {
        let ircvd: usize = utc.next().try_into().unwrap();
        rdb_check_add_unordered(&mut rdb, ircvd)?;
        rdb_check_expect_failure(&rdb, ircvd)?;
    }

    Ok(())
}

fn test_rdb_large_gaps(num_trials: usize) -> Result<(), Error> {
    let mut rdb = ReplayDB::new().unwrap();
    let mut rng = thread_rng();
    const MAX_LOG_GAP: usize = 12;

    // test sequential insertion
    let mut ircvd: usize = 0;
    for _ in 0..num_trials {
        rdb_check_add(&mut rdb, ircvd)?;
        rdb_check_expect_failure(&rdb, ircvd)?;

        let log_gap = rng.gen_range(0..MAX_LOG_GAP);
        ircvd += 1 << log_gap;
    }

    Ok(())
}

fn test_rdb_key_expiry() -> Result<(), Error> {
    let mut rdb = ReplayDB::new().unwrap();
    rdb.set_value(0x7ffffffe);

    if rdb.increment().is_err() {
        println!("rdb.increment of 0x7ffffffe failed");
        return Err(Error::Fail);
    }

    if rdb.value() != 0x7fffffff {
        println!("rdb valiue was not 0x7fffffff");
        return Err(Error::Fail);
    }

    match rdb.increment() {
        Err(Error::KeyExpired) => {}
        _ => {
            println!("rdb.increment of 0x7fffffff did not return Error::KeyExpired");
            return Err(Error::Fail);
        }
    }

    if rdb.value() != 0x7fffffff {
        println!("rdb valiue was not 0x7fffffff");
        return Err(Error::Fail);
    }

    Ok(())
}

fn test_rdb_db(num_trials: usize) -> Result<(), Error> {
    test_rdb_sequential(num_trials)?;
    test_rdb_non_sequential(num_trials)?;
    test_rdb_large_gaps(num_trials)?;
    test_rdb_key_expiry()?;
    Ok(())
}

fn rdb_check_adds_per_second(num_trials: usize) -> f64 {
    let mut rdb = ReplayDB::new().unwrap();

    let start = Instant::now();
    for i in (0..num_trials).step_by(3) {
        let idx: u32 = i.try_into().unwrap();
        rdb.check(idx + 2)
            .and_then(|_| rdb.add(idx + 2))
            .and_then(|_| rdb.check(idx + 1))
            .and_then(|_| rdb.add(idx + 1))
            .and_then(|_| rdb.check(idx))
            .and_then(|_| rdb.add(idx))
            .unwrap();
    }
    let elapsed = start.elapsed();

    let num_trials_f64: f64 = (num_trials as u32).try_into().unwrap();
    num_trials_f64 / elapsed.as_secs_f64()
}
