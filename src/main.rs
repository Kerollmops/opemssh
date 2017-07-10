extern crate opemssh;

use std::env;
use std::fs::File;

use opemssh::{pem_to_der, der_to_openssh};

fn main() {
    let filename = env::args().nth(1).expect("Give me a file");
    let der = pem_to_der(&mut File::open(filename).unwrap()).unwrap();

    // for c in der.as_slice() {
    //     print!("{:02x}", c.swap_bytes());
    // }
    // println!();

    let opssh = der_to_openssh(&der).unwrap();

    println!("{}", opssh);
}
