use crate::include::rdbx::*;
use crate::ut_sim::UTConnection;
use std::convert::{TryFrom, TryInto};
use std::os::raw::c_int;

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
        Err(_) => {
            println!("failed");
            1
        }
    }
}

fn sequential_test(num_trials: usize) -> Result<(), Error> {
    println!("\ttesting sequential insertion");
    let local = ExtendedSequenceNumber::new();
    let mut reference = ExtendedSequenceNumber::new();
    let mut num_bad_est: usize = 0;
    for _i in 0..2048 {
        let (estimated, _delta) = local.guess(reference as SequenceNumber);
        if reference != estimated {
            num_bad_est += 1;
        }

        reference.advance(1);
    }

    let failure_rate: f64 = (num_bad_est as f64) / (num_trials as f64);
    if failure_rate > FAILURE_THRESHOLD {
        println!(
            "error: failure rate too high ({} bad estimates in {} trials)",
            num_bad_est, num_trials
        );
        return Err(Error::AlgoFail);
    }

    println!("done");
    Ok(())
}

fn non_sequential_test(num_trials: usize) -> Result<(), Error> {
    println!("\ttesting non-sequential insertion");
    let mut local = ExtendedSequenceNumber::new();
    let mut num_bad_est: usize = 0;
    let mut utc = UTConnection::new();
    for _i in 0..num_trials {
        let ircvd = utc.next();
        let reference: ExtendedSequenceNumber = ircvd.into();

        let (estimated, delta) = local.guess(reference as SequenceNumber);

        let predicted: ExtendedSequenceNumber = (i64::try_from(local).unwrap()
            + i64::try_from(delta).unwrap())
        .try_into()
        .unwrap();
        if predicted != estimated {
            println!(
                " *bad delta*: local {} + delta {} != est {}\n",
                local, delta, estimated
            );
            return Err(Error::AlgoFail);
        }

        if delta > 0 {
            local.advance(delta as SequenceNumber);
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
        return Err(Error::AlgoFail);
    }

    println!("done");
    Ok(())
}
