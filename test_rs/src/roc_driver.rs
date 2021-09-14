#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]

mod ut_sim;

mod include {
    pub mod rdbx {
        use std::os::raw::c_int;

        pub type srtp_err_status_t = c_int;
        pub const srtp_err_status_ok: srtp_err_status_t = 0;
        pub const srtp_err_status_algo_fail: srtp_err_status_t = 1;

        pub type srtp_xtd_seq_num_t = u64;
        pub type srtp_sequence_number_t = u16;
    }
}

#[link(name = "srtp2")]
extern "C" {
    fn srtp_index_init(pi: *mut srtp_xtd_seq_num_t);
    fn srtp_index_advance(pi: *mut srtp_xtd_seq_num_t, s: srtp_sequence_number_t);
    fn srtp_index_guess(
        local: *const srtp_xtd_seq_num_t,
        guess: *mut srtp_xtd_seq_num_t,
        s: srtp_sequence_number_t,
    ) -> i32;
}

use include::rdbx::*;
use ut_sim::UTConnection;

use std::convert::{TryFrom, TryInto};
use std::process::exit;

fn main() {
    println!("rollover counter test driver");
    println!("David A. McGrew");
    println!("Cisco Systems, Inc.");

    println!("testing index functions...");

    let status = roc_test(1 << 18);
    if status != srtp_err_status_ok {
        println!("failed");
        exit(status);
    }
    println!("passed");
}

fn roc_test(num_trials: usize) -> srtp_err_status_t {
    const FAILURE_THRESHOLD: f64 = 0.01;
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
        return srtp_err_status_algo_fail;
    }
    println!("done");

    println!("\ttesting non-sequential insertion");
    unsafe {
        srtp_index_init(&mut local);
        srtp_index_init(&mut estimated);
        srtp_index_init(&mut reference);
    };

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
            return srtp_err_status_algo_fail;
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
        return srtp_err_status_algo_fail;
    }
    println!("done");

    return 0;
}
