use crate::include::rdb::*;
use crate::ut_sim::UTConnection;
use rand::{thread_rng, Rng};
use std::convert::TryInto;
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

fn rdb_check_add(rdb: &mut srtp_rdb_t, idx: usize) -> Result<(), srtp_err_status_t> {
    let idx: u32 = idx.try_into().unwrap();
    if unsafe { srtp_rdb_check(rdb, idx).is_err() } {
        println!("rdb_check failed at index {}", idx);
        return Err(srtp_err_status_fail);
    }

    if unsafe { srtp_rdb_add_index(rdb, idx).is_err() } {
        println!("rdb_add_index failed at index {}", idx);
        return Err(srtp_err_status_fail);
    }

    Ok(())
}

fn rdb_check_expect_failure(rdb: &srtp_rdb_t, idx: usize) -> Result<(), srtp_err_status_t> {
    let idx: u32 = idx.try_into().unwrap();
    let status = unsafe { srtp_rdb_check(rdb, idx) };
    if status != srtp_err_status_replay_old && status != srtp_err_status_replay_fail {
        println!("rdb_check failed at index {} (false positive)", idx);
        return Err(srtp_err_status_fail);
    }
    Ok(())
}

fn rdb_check_add_unordered(rdb: &mut srtp_rdb_t, idx: usize) -> Result<(), srtp_err_status_t> {
    let idx: u32 = idx.try_into().unwrap();

    let status = unsafe { srtp_rdb_check(rdb, idx) };
    if !status.is_ok() && status != srtp_err_status_replay_old {
        println!("rdb_check_add_unordered failed at index {}", idx);
        return Err(srtp_err_status_algo_fail);
    }

    if status == srtp_err_status_replay_old {
        return Ok(());
    }

    if unsafe { srtp_rdb_add_index(rdb, idx).is_err() } {
        println!("rdb_add_index failed at index {}", idx);
        return Err(srtp_err_status_algo_fail);
    }

    Ok(())
}

fn test_rdb_sequential(num_trials: usize) -> Result<(), srtp_err_status_t> {
    let mut rdb = srtp_rdb_t::default();
    unsafe { srtp_rdb_init(&mut rdb).as_result()? };

    for idx in 0..num_trials {
        rdb_check_add(&mut rdb, idx)?;
        rdb_check_expect_failure(&rdb, idx)?;
    }

    Ok(())
}

fn test_rdb_non_sequential(num_trials: usize) -> Result<(), srtp_err_status_t> {
    let mut rdb = srtp_rdb_t::default();
    unsafe { srtp_rdb_init(&mut rdb).as_result()? };

    let mut utc = UTConnection::new();

    for _ in 0..num_trials {
        let ircvd: usize = utc.next().try_into().unwrap();
        rdb_check_add_unordered(&mut rdb, ircvd)?;
        rdb_check_expect_failure(&rdb, ircvd)?;
    }

    Ok(())
}

fn test_rdb_large_gaps(num_trials: usize) -> Result<(), srtp_err_status_t> {
    let mut rdb = srtp_rdb_t::default();
    unsafe { srtp_rdb_init(&mut rdb).as_result()? };

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

fn test_rdb_key_expiry() -> Result<(), srtp_err_status_t> {
    let mut rdb = srtp_rdb_t::default();
    unsafe { srtp_rdb_init(&mut rdb).as_result()? };

    rdb.window_start = 0x7ffffffe;
    if unsafe { srtp_rdb_increment(&mut rdb).is_err() } {
        println!("srtp_rdb_increment of 0x7ffffffe failed");
        return Err(srtp_err_status_fail);
    }
    if unsafe { srtp_rdb_get_value(&rdb) } != 0x7fffffff {
        println!("rdb valiue was not 0x7fffffff");
        return Err(srtp_err_status_fail);
    }
    if unsafe { srtp_rdb_increment(&mut rdb) } != srtp_err_status_key_expired {
        println!("srtp_rdb_increment of 0x7fffffff did not return srtp_err_status_key_expired");
        return Err(srtp_err_status_fail);
    }
    if unsafe { srtp_rdb_get_value(&rdb) } != 0x7fffffff {
        println!("rdb valiue was not 0x7fffffff");
        return Err(srtp_err_status_fail);
    }

    Ok(())
}

fn test_rdb_db(num_trials: usize) -> Result<(), srtp_err_status_t> {
    test_rdb_sequential(num_trials)?;
    test_rdb_non_sequential(num_trials)?;
    test_rdb_large_gaps(num_trials)?;
    test_rdb_key_expiry()?;
    Ok(())
}

fn rdb_check_adds_per_second(num_trials: usize) -> f64 {
    let mut rdb = srtp_rdb_t::default();
    unsafe { srtp_rdb_init(&mut rdb).as_result().unwrap() };

    let start = Instant::now();
    for i in (0..num_trials).step_by(3) {
        let idx: u32 = i.try_into().unwrap();
        unsafe {
            srtp_rdb_check(&mut rdb, idx + 2)
                .as_result()
                .and_then(|_| srtp_rdb_add_index(&mut rdb, idx + 2).as_result())
                .and_then(|_| srtp_rdb_check(&rdb, idx + 1).as_result())
                .and_then(|_| srtp_rdb_add_index(&mut rdb, idx + 1).as_result())
                .and_then(|_| srtp_rdb_check(&rdb, idx).as_result())
                .and_then(|_| srtp_rdb_add_index(&mut rdb, idx).as_result())
                .unwrap();
        }
    }
    let elapsed = start.elapsed();

    let num_trials_f64: f64 = (num_trials as u32).try_into().unwrap();
    num_trials_f64 / elapsed.as_secs_f64()
}
