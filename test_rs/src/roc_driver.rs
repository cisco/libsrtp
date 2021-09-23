use crate::include::rdbx::*;
use crate::ut_sim::UTConnection;
use std::convert::{TryFrom, TryInto};

const FAILURE_THRESHOLD: f64 = 0.01;
const NUM_TRIALS: usize = 1 << 18;

#[no_mangle]
pub extern "C" fn roc_driver_main() -> c_int {
    println!("rollover counter test driver");
    println!("David A. McGrew");
    println!("Cisco Systems, Inc.");

    println!("testing index functions...");

    match sequential_test(NUM_TRIALS).and(non_sequential_test(NUM_TRIALS)) {
        Ok(_) => {
            println!("passed");
            0
        }
        Err(err) => {
            println!("failed");
            err.try_into().unwrap()
        }
    }
}

fn sequential_test(num_trials: usize) -> Result<(), srtp_err_status_t> {
    let mut local: srtp_xtd_seq_num_t = 0;
    let mut estimated: srtp_xtd_seq_num_t = 0;
    let mut reference: srtp_xtd_seq_num_t = 0;

    println!("\ttesting sequential insertion");
    unsafe {
        srtp_index_init(&mut local);
        srtp_index_init(&mut estimated);
        srtp_index_init(&mut reference);
    };

    let mut num_bad_est: usize = 0;
    for _i in 0..2048 {
        unsafe { srtp_index_guess(&local, &mut estimated, reference as srtp_sequence_number_t) };
        if reference != estimated {
            num_bad_est += 1;
        }
        unsafe { srtp_index_advance(&mut reference, 1) };
    }

    let failure_rate: f64 = (num_bad_est as f64) / (num_trials as f64);
    if failure_rate > FAILURE_THRESHOLD {
        println!(
            "error: failure rate too high ({} bad estimates in {} trials)",
            num_bad_est, num_trials
        );
        return Err(srtp_err_status_algo_fail);
    }

    println!("done");
    Ok(())
}

fn non_sequential_test(num_trials: usize) -> Result<(), srtp_err_status_t> {
    let mut local: srtp_xtd_seq_num_t = 0;
    let mut estimated: srtp_xtd_seq_num_t = 0;
    let mut reference: srtp_xtd_seq_num_t = 0;

    println!("\ttesting non-sequential insertion");
    unsafe {
        srtp_index_init(&mut local);
        srtp_index_init(&mut estimated);
        srtp_index_init(&mut reference);
    };

    let mut num_bad_est: usize = 0;
    let mut utc = UTConnection::new();
    for _i in 0..num_trials {
        let ircvd = utc.next();
        reference = ircvd.into();

        let delta = unsafe {
            srtp_index_guess(&local, &mut estimated, reference as srtp_sequence_number_t)
        };

        let predicted: srtp_xtd_seq_num_t = (i64::try_from(local).unwrap()
            + i64::try_from(delta).unwrap())
        .try_into()
        .unwrap();
        if predicted != estimated {
            println!(
                " *bad delta*: local {} + delta {} != est {}\n",
                local, delta, estimated
            );
            return Err(srtp_err_status_algo_fail);
        }

        if delta > 0 {
            unsafe { srtp_index_advance(&mut local, delta as u16) };
        }

        if reference != estimated {
            num_bad_est += 1;
            local = reference;
        }
    }

    let failure_rate: f64 = (num_bad_est as f64) / (num_trials as f64);
    if failure_rate > FAILURE_THRESHOLD {
        println!(
            "error: failure rate too high ({} bad estimates in {} trials)",
            num_bad_est, num_trials
        );
        return Err(srtp_err_status_algo_fail);
    }

    println!("done");
    Ok(())
}
