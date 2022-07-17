#![no_std]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

// pub use std::*;

// #[cfg(test)]
// extern crate serde_json;
// #[cfg(test)]
//
// #[macro_use]
// extern crate serde_derive;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_alloc as alloc;

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tunittest;
// pub mod aes;

#[path = "arch/arch64.rs"]
pub mod arch;
pub mod errors;
// // pub mod gcm;
pub mod hash256;
pub mod hash384;
pub mod hash512;
// pub mod nhs;
pub mod rand;
// pub mod sha3;
pub mod types;

#[cfg(feature = "bls381")]
#[path = "./"]
pub mod bls381 {
    #[path = "roms/rom_bls381.rs"]
    pub mod rom;
    pub mod big;
    pub mod bls381;
    pub mod dbig;
    pub mod ecp;
    pub mod ecp2;
    pub mod fp;
    pub mod fp12;
    pub mod fp2;
    pub mod fp4;
    pub mod hash_to_curve;
    pub mod mpin;
    pub mod pair;
}
