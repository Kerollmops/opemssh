extern crate yasna;
extern crate base64;
extern crate num;

const RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];
const SSH_RSA_TEXT: &str = "ssh-rsa";

use std::io::{Read, BufRead};
use std::io::{self, BufReader};
use std::mem;
use num::bigint::BigInt;
use base64::{decode, encode};
use yasna::parse_der;
use yasna::models::ObjectIdentifier;

#[derive(Debug)]
struct PublicDer {
    object_identifier: ObjectIdentifier,
    exponent: BigInt,
    modulus: BigInt,
}

// TODO: check header name
pub fn pem_to_der<R: Read>(pem: &mut R) -> io::Result<Vec<u8>> {
    let buff = BufReader::new(pem);
    let mut pem = String::new();

    for line in buff.lines() {
        let line = line?;
        if !line.starts_with('-') {
            pem.extend(line.chars());
        }
    }

    Ok(decode(&pem).unwrap())
}

pub fn der_to_openssh(der: &[u8]) -> Result<String, ()> {
    let public_der = parse_der(der, |reader| {
        reader.read_sequence(|reader| {
            let oid = reader.next().read_sequence(|reader| {
                let oid = reader.next().read_oid()?; // TODO: check object identifier
                let _ = reader.next().read_null()?;
                Ok(oid)
            })?;

            let bs = reader.next().read_bitvec()?.to_bytes();
            let (n, e) = parse_der(&bs, |reader| {
                reader.read_sequence(|reader| {
                    let n = reader.next().read_bigint()?;
                    let e = reader.next().read_bigint()?;
                    Ok((n, e))
                })
            })?;

            Ok(PublicDer {
                object_identifier: oid,
                exponent: e,
                modulus: n,
            })
        })
    }).expect("Ooops");

    if public_der.object_identifier.components().as_slice() != &RSA_ENCRYPTION {
        panic!("Ooops 2")
    }

    // let exp_len = size_len + 0;

    // println!("{:?}", public_der.exponent.bits());

    let mut openssh_key = Vec::with_capacity(10000); // TODO: compute this

    let len = (SSH_RSA_TEXT.len() as u32).swap_bytes();
    let text_len: [u8; 4] = unsafe { mem::transmute_copy(&len) };
    openssh_key.extend_from_slice(&text_len);
    openssh_key.extend_from_slice(SSH_RSA_TEXT.as_bytes());

    // TODO: change names
    let exponent_bits = (((public_der.exponent.bits() - 1) / 8 + 1) as u32).swap_bytes();
    let exponent_len: [u8; 4] = unsafe { mem::transmute_copy(&exponent_bits) };
    openssh_key.extend_from_slice(&exponent_len);
    let (_, bytes) = public_der.exponent.to_bytes_be();
    openssh_key.extend_from_slice(&bytes);

    let modulus_bits = (((public_der.modulus.bits() - 1) / 8 + 1) as u32).swap_bytes();
    let modulus_len: [u8; 4] = unsafe { mem::transmute_copy(&modulus_bits) };
    openssh_key.extend_from_slice(&modulus_len);
    let (_, bytes) = public_der.modulus.to_bytes_be();
    openssh_key.extend_from_slice(&bytes);

    // println!("{:?}", openssh_key);

    // TODO: ugly as shit
    Ok("ssh-rsa ".to_string() + &encode(&openssh_key))
    // Ok(encode(&openssh_key))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
    }
}
