extern crate yasna;
extern crate base64;
extern crate num;
extern crate byteorder;

const RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];
const SSH_RSA_TEXT: &str = "ssh-rsa";

use std::io::{Read, BufRead};
use std::io::{self, BufReader};
use num::bigint::BigInt;
use base64::{decode, encode};
use yasna::parse_der;
use yasna::models::ObjectIdentifier;
use byteorder::BigEndian;
use byteorder::WriteBytesExt;

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
                let oid = reader.next().read_oid()?;
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

    let iod = public_der.object_identifier.components().as_slice();
    if iod != RSA_ENCRYPTION {
        panic!("Ooops 2")
    }

    // let exp_len = size_len + 0;

    let mut openssh_key = Vec::with_capacity(10000); // TODO: compute this

    // write the size of the 'ssh-rsa' text
    let ssh_rsa_text_len = SSH_RSA_TEXT.len() as u32;
    openssh_key.write_u32::<BigEndian>(ssh_rsa_text_len).unwrap(); // TODO: don't unwrap !
    // write the 'ssh-rsa' text itself
    openssh_key.extend_from_slice(SSH_RSA_TEXT.as_bytes());

    // write the size of the exponent
    let exp_bits_size = ((public_der.exponent.bits() - 1) / 8 + 1) as u32;
    openssh_key.write_u32::<BigEndian>(exp_bits_size).unwrap();
    // write the exponent itself
    let (_, bytes) = public_der.exponent.to_bytes_be();
    openssh_key.extend_from_slice(&bytes);

    // write the size of the modulus
    let mod_bits_size = ((public_der.modulus.bits() - 1) / 8 + 1) as u32;
    openssh_key.write_u32::<BigEndian>(mod_bits_size).unwrap();
    // write the modulus itself
    let (_, bytes) = public_der.modulus.to_bytes_be();
    openssh_key.extend_from_slice(&bytes);

    let mut openssh_key = encode(&openssh_key);
    openssh_key.insert_str(0, "ssh-rsa ");
    Ok(openssh_key)
}

// #[cfg(test)]
// mod tests {
//     #[test]
//     fn it_works() {
//     }
// }
