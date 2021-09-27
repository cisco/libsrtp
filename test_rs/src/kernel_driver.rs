use crate::include::kernel::*;
use clap::Clap;
use std::os::raw::c_int;

#[derive(Clap)]
struct Config {
    #[clap(short)]
    validation: bool,

    #[clap(short)]
    debug_module: Option<String>,
}

#[no_mangle]
pub extern "C" fn kernel_driver_main() -> c_int {
    let kernel = match CryptoKernel::new() {
        Ok(x) => x,
        Err(err) => {
            println!("error: srtp_crypto_kernel init failed ({:?})", err);
            return 1;
        }
    };
    println!("srtp_crypto_kernel successfully initalized");

    let config = Config::parse();

    if let Some(ref debug_module) = config.debug_module {
        if let Err(err) = kernel.set_debug_module(debug_module, true) {
            println!(
                "error: set debug module ({}) failed ({:?})",
                debug_module, err
            );
        }
    }

    if config.validation {
        println!("checking srtp_crypto_kernel status...");
        if let Err(err) = kernel.status() {
            println!("failed ({:?})", err);
            return 1;
        }
        println!("srtp_crypto_kernel passed self-tests...");
    }

    0
}
