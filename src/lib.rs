extern crate rand_mt;

mod mhycrypt;
mod api;

pub mod prelude {
    pub use super::{mhy_xor, mhy_generate_key, load_ec2b_keys, load_rsa_keys};
}

pub use mhycrypt::{mhy_xor, mhy_generate_key, load_ec2b_keys, load_rsa_keys};
