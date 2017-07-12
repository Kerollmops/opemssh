extern crate yasna;
extern crate base64;
extern crate num;
extern crate byteorder;

const RSA_ENCRYPTION: [u64; 7] = [1, 2, 840, 113549, 1, 1, 1];
const SSH_RSA_TEXT: &str = "ssh-rsa";

use std::io::{Read, BufRead};
use std::io::{self, BufReader};
use num::bigint::{BigInt, Sign};
use base64::{decode, encode, DecodeError};
use yasna::{parse_der, ASN1Error};
use yasna::models::ObjectIdentifier;
use byteorder::BigEndian;
use byteorder::WriteBytesExt;

#[derive(Debug)]
pub enum Error {
    IoError(io::Error),
    DecodeError(DecodeError),
    ASN1Error(ASN1Error),
    InvalidSshaRsa,
}

#[derive(Debug)]
struct PublicDer {
    object_identifier: ObjectIdentifier,
    exponent: BigInt,
    modulus: BigInt,
}

// TODO: check header name
pub fn pem_to_der<R: Read>(pem: &mut R) -> Result<Vec<u8>, Error> {
    let buff = BufReader::new(pem);
    let mut pem = String::new();

    for line in buff.lines() {
        let line = line.map_err(Error::IoError)?;
        if !line.starts_with('-') {
            pem.extend(line.chars());
        }
    }

    Ok(decode(&pem).map_err(Error::DecodeError)?)
}

pub fn der_to_openssh(der: &[u8]) -> Result<String, Error> {
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
    }).map_err(Error::ASN1Error)?;

    let iod = public_der.object_identifier.components().as_slice();
    if iod != RSA_ENCRYPTION {
        return Err(Error::InvalidSshaRsa);
    }

    // TODO: compute capacity
    let mut openssh_key = Vec::new();

    // write the size of the 'ssh-rsa' text
    let ssh_rsa_text_len = SSH_RSA_TEXT.len() as u32;
    openssh_key.write_u32::<BigEndian>(ssh_rsa_text_len).map_err(Error::IoError)?;
    // write the 'ssh-rsa' text itself
    openssh_key.extend_from_slice(SSH_RSA_TEXT.as_bytes());

    // write the size of the exponent
    let exp_bits_size = (public_der.exponent.bits() / 8 + 1) as u32;
    openssh_key.write_u32::<BigEndian>(exp_bits_size).map_err(Error::IoError)?;
    let (sign, mut bytes) = public_der.exponent.to_bytes_be();
    // add a byte to toggle the sign bit
    if bytes.len() < exp_bits_size as usize {
        bytes.insert(0, 0);
    }
    bytes[0] |= if sign == Sign::Minus { 0b1000_0000 } else { 0 };
    // write the exponent itself (with sign bit)
    openssh_key.extend_from_slice(&bytes);

    // write the size of the modulus
    let mod_bits_size = (public_der.modulus.bits() / 8 + 1) as u32;
    openssh_key.write_u32::<BigEndian>(mod_bits_size).map_err(Error::IoError)?;

    let (sign, mut bytes) = public_der.modulus.to_bytes_be();
    // add a byte to toggle the sign bit
    if bytes.len() < mod_bits_size as usize {
        bytes.insert(0, 0);
    }
    bytes[0] |= if sign == Sign::Minus { 0b1000_0000 } else { 0 };
    // write the modulus itself (with sign bit)
    openssh_key.extend_from_slice(&bytes);

    let mut openssh_key = encode(&openssh_key);
    openssh_key.insert_str(0, "ssh-rsa ");
    Ok(openssh_key)
}
