use crate::include::rdbx::*;
use crate::ut_sim::UTConnection;
use clap::Clap;
use rand::{thread_rng, Rng};
use std::convert::TryInto;
use std::time::Instant;

// XXX(RLB) Might be able to replace this with Clap usage and just failing.
fn usage() -> c_int {
    println!("usage: rdbx_driver [ -t | -v ]");
    255
}

#[derive(Clap)]
struct Config {
    #[clap(short)]
    timing: bool,

    #[clap(short)]
    validation: bool,
}

const VALIDATION_TRIALS: usize = 1 << 12;
const TIMING_TRIALS: usize = 1 << 18;
const SMALL_WINDOW: usize = 128;
const LARGE_WINDOW: usize = 1024;

#[no_mangle]
extern "C" fn rdbx_driver_main() -> c_int {
    println!("rdbx (replay database w/ extended range) test driver");
    println!("David A. McGrew");
    println!("Cisco Systems, Inc.");

    let config = Config::parse();
    if !config.timing && !config.validation {
        return usage();
    }

    if config.validation {
        println!("testing srtp_rdbx_t (ws={})...", SMALL_WINDOW);
        match test_replay_dbx(VALIDATION_TRIALS, SMALL_WINDOW) {
            Ok(_) => println!("passed"),
            Err(err) => {
                println!("failed");
                return err.try_into().unwrap();
            }
        }

        println!("testing srtp_rdbx_t (ws={})...", LARGE_WINDOW);
        match test_replay_dbx(VALIDATION_TRIALS, LARGE_WINDOW) {
            Ok(_) => println!("passed"),
            Err(err) => {
                println!("failed");
                return err.try_into().unwrap();
            }
        }
    }

    if config.timing {
        let rate = rdbx_check_adds_per_second(TIMING_TRIALS, SMALL_WINDOW);
        println!("rdbx_check/replay_adds per second (ws=128): {:e}\n", rate);

        let rate = rdbx_check_adds_per_second(TIMING_TRIALS, LARGE_WINDOW);
        println!("rdbx_check/replay_adds per second (ws=1024): {:e}\n", rate);
    }

    0
}

// rdbx_check_add(rdbx, idx) checks a known-to-be-good idx against
// rdbx, then adds it.  if a failure is detected (i.e., the check
// indicates that the value is already in rdbx) then
// srtp_err_status_algo_fail is returned.
fn rdbx_check_add(rdbx: &mut srtp_rdbx_t, idx: usize) -> Result<(), srtp_err_status_t> {
    let mut est: srtp_xtd_seq_num_t = 0;
    let delta = unsafe { srtp_index_guess(&rdbx.index, &mut est, idx as u16) };

    if unsafe { srtp_rdbx_check(rdbx, delta).is_err() } {
        println!("replay_check failed at index {}", idx);
        return Err(srtp_err_status_algo_fail);
    }

    if unsafe { srtp_rdbx_add_index(rdbx, delta).is_err() } {
        println!("rdbx_add_index failed at index {}", idx);
        return Err(srtp_err_status_algo_fail);
    }

    Ok(())
}

// checks that a sequence number idx is in the replay database
// and thus will be rejected
fn rdbx_check_expect_failure(rdbx: &mut srtp_rdbx_t, idx: usize) -> Result<(), srtp_err_status_t> {
    let mut est: srtp_xtd_seq_num_t = 0;
    let delta = unsafe { srtp_index_guess(&rdbx.index, &mut est, idx as u16) };

    if unsafe { srtp_rdbx_check(rdbx, delta).is_ok() } {
        println!("delta: {}", delta);
        println!("replay_check failed at index {} (false positive)", idx);
        return Err(srtp_err_status_algo_fail);
    }

    Ok(())
}

fn rdbx_check_add_unordered(rdbx: &mut srtp_rdbx_t, idx: usize) -> Result<(), srtp_err_status_t> {
    let mut est: srtp_xtd_seq_num_t = 0;
    let delta = unsafe { srtp_index_guess(&rdbx.index, &mut est, idx as u16) };

    let status = unsafe { srtp_rdbx_check(rdbx, delta) };
    if !status.is_ok() && status != srtp_err_status_replay_old {
        println!("replay_check_add_unordered failed at index {}", idx);
        return Err(srtp_err_status_algo_fail);
    }

    if status == srtp_err_status_replay_old {
        return Ok(());
    }

    if unsafe { srtp_rdbx_add_index(rdbx, delta).is_err() } {
        println!("rdbx_add_index failed at index {}", idx);
        return Err(srtp_err_status_algo_fail);
    }

    Ok(())
}

// XXX(RLB) This function fails to deallocate `rdbx` in error cases
fn test_rdbx_sequential(num_trials: usize, window_size: usize) -> Result<(), srtp_err_status_t> {
    let mut rdbx = srtp_rdbx_t::default();
    unsafe { srtp_rdbx_init(&mut rdbx, window_size.try_into().unwrap()).as_result()? };

    // test sequential insertion
    print!("\ttesting sequential insertion...");
    for idx in 0..num_trials {
        rdbx_check_add(&mut rdbx, idx)?;
    }
    println!("passed");

    let num_fp_trials = num_trials % 0x10000;
    if num_fp_trials == 0 {
        println!("warning: no false positive tests performed\n");
    }

    // test for false positives by checking all of the index
    // values which we've just added
    //
    // note that we limit the number of trials here, since allowing the
    // rollover counter to roll over would defeat this test
    print!("\ttesting for false positives...");
    for idx in 0..num_fp_trials {
        rdbx_check_expect_failure(&mut rdbx, idx)?;
    }
    println!("passed");

    unsafe { srtp_rdbx_dealloc(&mut rdbx) };
    Ok(())
}

// test non-sequential insertion
//
// this test covers only fase negatives, since the values returned
// by UTConnection::next() are distinct
fn test_rdbx_non_sequential(
    num_trials: usize,
    window_size: usize,
) -> Result<(), srtp_err_status_t> {
    let mut rdbx = srtp_rdbx_t::default();
    unsafe { srtp_rdbx_init(&mut rdbx, window_size.try_into().unwrap()).as_result()? };

    let mut utc = UTConnection::new();

    // test sequential insertion
    print!("\ttesting non-sequential insertion...");
    for _ in 0..num_trials {
        let ircvd: usize = utc.next().try_into().unwrap();
        rdbx_check_add_unordered(&mut rdbx, ircvd)?;
        rdbx_check_expect_failure(&mut rdbx, ircvd)?;
    }
    println!("passed");

    unsafe { srtp_rdbx_dealloc(&mut rdbx) };
    Ok(())
}

fn test_rdbx_large_gaps(num_trials: usize, window_size: usize) -> Result<(), srtp_err_status_t> {
    let mut rdbx = srtp_rdbx_t::default();
    unsafe { srtp_rdbx_init(&mut rdbx, window_size.try_into().unwrap()).as_result()? };

    let mut rng = thread_rng();
    const MAX_LOG_GAP: usize = 12;

    // test sequential insertion
    print!("\ttesting insertion with large gaps...");
    let mut ircvd: usize = 0;
    for _ in 0..num_trials {
        rdbx_check_add(&mut rdbx, ircvd)?;
        rdbx_check_expect_failure(&mut rdbx, ircvd)?;

        let log_gap = rng.gen_range(0..MAX_LOG_GAP);
        ircvd += 1 << log_gap;
    }
    println!("passed");

    unsafe { srtp_rdbx_dealloc(&mut rdbx) };
    Ok(())
}

fn test_replay_dbx(num_trials: usize, window_size: usize) -> Result<(), srtp_err_status_t> {
    test_rdbx_sequential(num_trials, window_size)?;
    test_rdbx_non_sequential(num_trials, window_size)?;
    test_rdbx_large_gaps(num_trials, window_size)?;
    Ok(())
}

fn rdbx_check_adds_per_second(num_trials: usize, window_size: usize) -> f64 {
    let mut rdbx = srtp_rdbx_t::default();

    let status = unsafe { srtp_rdbx_init(&mut rdbx, window_size.try_into().unwrap()) };
    if status.is_err() {
        println!("replay_init failed\n");
        std::process::exit(1);
    }

    let mut failures = 0usize;
    let start = Instant::now();
    for i in 0..num_trials {
        let mut est: srtp_xtd_seq_num_t = 0;
        let delta = unsafe { srtp_index_guess(&rdbx.index, &mut est, i as u16) };

        if unsafe { srtp_rdbx_check(&rdbx, delta).is_err() } {
            failures += 1;
        } else if unsafe { srtp_rdbx_add_index(&mut rdbx, delta).is_err() } {
            failures += 1;
        }
    }
    let elapsed = start.elapsed();

    println!("number of failures: {}", failures);
    unsafe { srtp_rdbx_dealloc(&mut rdbx) };

    let num_trials_f64: f64 = (num_trials as u32).try_into().unwrap();
    num_trials_f64 / elapsed.as_secs_f64()
}
