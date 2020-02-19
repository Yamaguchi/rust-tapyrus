// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

//! Signature for block proof
//!
//! Implementation for Schnorr signature which is used as block proof.
//!

use std::error;
use std::fmt;
use std::borrow::Borrow;

use secp256k1::SecretKey;
use hashes::{sha256, HashEngine, Hash};

use util::key::{PublicKey, PrivateKey};
use util::prime::jacobi;
use util::rfc7969::nonce_rfc6979;


/// Generator for secp256k1 elliptic curve
pub const GENERATOR: [u8; 33] = [
    0x02,
    0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
    0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
    0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
    0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98
];

/// The size of scalar value on secp256k1 curve
pub const SECP256K1_SCALAR_SIZE: usize = 32;

/// Schnorr signature struct
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub struct Signature {
    /// R.x
    pub r_x: [u8; SECP256K1_SCALAR_SIZE],
    /// sigma
    pub sigma: [u8; SECP256K1_SCALAR_SIZE],
}

impl Signature {
    /// signing to message
    pub fn sign(privkey: &PrivateKey, message: &[u8; 32]) -> Result<Self, Error> {
        let ctx = secp256k1::Secp256k1::signing_only();
        let sk = privkey.key.borrow();

        let pk = secp256k1::PublicKey::from_secret_key(&ctx, sk);

        // Generate k
        let mut k = Self::generate_k(sk, message);

        // TODO: Check private key and k is not zero
        // this is no need because all secret key instance checked.

        // Compute R = k * G
        let r = secp256k1::PublicKey::from_secret_key(&ctx, &k);

        // Negate k if value of jacobi(R.y) is not 1
        if jacobi(&r.serialize_uncompressed()[33..]) != 1 {
            k.negate_assign();
        }

        // Compute e = sha256(R.x, pk, message)
        let e = Self::compute_e(&r.serialize()[1..33], &pk, message)?;

        // Compute s = k + ep
        let sigma = {
            let mut result = e.clone();
            result.mul_assign(&sk[..])?;
            result.add_assign(&k[..])?;
            result
        };

        let mut r_x = [0u8; 32];
        r_x.clone_from_slice(&r.serialize()[1..33]);

        Ok(Signature { r_x, sigma: to_bytes(&sigma) })
    }

    /// Verify signature
    pub fn verify(&self, message: &[u8], pk: &PublicKey) -> Result<(), Error> {
        let ctx = secp256k1::Secp256k1::verification_only();

        // TODO: check pk is not infinity.

        // Extract s
        let s = secp256k1::SecretKey::from_slice(&self.sigma[..])?;

        // Compute e
        let mut e = Self::compute_e(&self.r_x[..], &pk.key, message)?;

        // Compute R = sG - eP
        let r = {
            e.negate_assign();
            let minus_ep = {
                let mut result = pk.key.clone();
                result.mul_assign(&ctx, &e[..])?;
                result
            };

            let sg = {
                let mut result = secp256k1::PublicKey::from_slice(&GENERATOR[..]).unwrap();
                result.mul_assign(&ctx, &s[..])?;
                result
            };

            sg.combine(&minus_ep)?
        };

        // TODO: check R is not infinity.

        // Check that R.x is what we expect
        if &r.serialize()[1..33] != self.r_x {
            return Err(Error::InvalidSignature);
        }

        // Check that jacobi(R.y) is 1
        if jacobi(&r.serialize_uncompressed()[33..]) != 1 {
            return Err(Error::InvalidSignature);
        }

        Ok(())
    }

    /// Compute e
    fn compute_e(r_x: &[u8], pk: &secp256k1::PublicKey, message: &[u8]) -> Result<SecretKey, secp256k1::Error> {
        let mut engine = sha256::Hash::engine();
        engine.input(r_x);
        engine.input(&pk.serialize()[..]);
        engine.input(message);
        let hash = sha256::Hash::from_engine(engine);

        Ok(SecretKey::from_slice(&hash[..])?)
    }

    fn generate_k(sk: &SecretKey, message: &[u8; 32]) -> SecretKey {
        // "SCHNORR + SHA256"
        const ALGO16: [u8; 16] = [
            83, 67, 72, 78, 79, 82, 82, 32, 43, 32, 83, 72, 65, 50, 53, 54
        ];

        let mut count: u32 = 0;

        loop {
            let nonce = nonce_rfc6979(
                message,
                sk,
                &ALGO16,
                None,
                count
            );
            count += 1;

            if let Ok(k) = SecretKey::from_slice(&nonce[..]) {
                return k;
            }
        }
    }
}

fn to_bytes(sk: &secp256k1::SecretKey) -> [u8; 32] {
    let mut r = [0u8; 32];
    r.clone_from_slice(&sk[..]);
    r
}

impl Default for Signature {
    fn default() -> Self {
        Signature {
            sigma: [0u8; SECP256K1_SCALAR_SIZE],
            r_x: [0u8; SECP256K1_SCALAR_SIZE],
        }
    }
}

impl_consensus_encoding!(Signature, r_x, sigma);
serde_struct_impl!(Signature, r_x, sigma);

/// Signature error
#[derive(Debug)]
pub enum Error {
    /// Invalid Signature Error
    InvalidSignature,
    /// secp256k1 error
    Secp256k1Error(secp256k1::Error),
}

#[doc(hidden)]
impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error {
        Error::Secp256k1Error(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Secp256k1Error(ref e) => fmt::Display::fmt(e, f),
            Error::InvalidSignature => {
                f.write_str(error::Error::description(self))
            }
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Secp256k1Error(ref e) => e.description(),
            Error::InvalidSignature => "Invalid signature",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Secp256k1Error(ref e) => Some(e),
            Error::InvalidSignature => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use hex::decode as hex_decode;

    use hashes::core::str::FromStr;
    use hashes::Hash;
    use consensus::encode::{deserialize, serialize};
    use util::signature::Signature;
    use util::key::{PrivateKey, PublicKey};

    #[test]
    fn test_sign_schnorr() {
        for n in 0..16 {
            let msg = {
                let m = format!("Very secret message {}: 11", n);
                let hash = hashes::sha256::Hash::hash(m.as_bytes());
                hash.into_inner()
            };

            let key = PrivateKey::from_wif("5HxWvvfubhXpYYpS3tJkw6fq9jE9j18THftkZjHHfmFiWtmAbrj").unwrap();

            let sign = Signature::sign(&key, &msg).unwrap();

            let ctx = secp256k1::Secp256k1::signing_only();
            assert!(sign.verify(&msg[..], &key.public_key(&ctx)).is_ok());
        }
    }

    #[test]
    fn signature_test() {
        let sig_data =
            hex_decode("6ba8aee2e8cee077cb4a799c770e417fb750586ee5dd9f61db65f5158a596e77aaa87e4fec16c70b102bbe99a6c4fe77be424a44a2f5cfdc5fe04d5b4bca799c").unwrap();

        let r_x =
            hex_decode("6ba8aee2e8cee077cb4a799c770e417fb750586ee5dd9f61db65f5158a596e77").unwrap();
        let sigma =
            hex_decode("aaa87e4fec16c70b102bbe99a6c4fe77be424a44a2f5cfdc5fe04d5b4bca799c").unwrap();

        let decode: Result<Signature, _> = deserialize(&sig_data);
        assert!(decode.is_ok());

        let real_decode = decode.unwrap();
        assert_eq!(&real_decode.sigma[..], sigma.as_slice());
        assert_eq!(&real_decode.r_x[..], r_x.as_slice());
        assert_eq!(serialize(&real_decode), sig_data);
    }

    #[test]
    fn test_verify() {
        let signature =
            hex_decode("8ecf8e95c1b31f9cf765912f77876d7782df71a50612b25930311d8746f5f61b9b22b5ee08ac148e8fe143b37a45976937a2d38eacf600343323f91614917dd5").unwrap();
        let signature: Signature = deserialize(&signature).unwrap();

        let message =
            hex_decode("b77bba2a538d76d23ec211516afeb6db31c3266c6867e00c5c584f01c78da5ca").unwrap();



        let pubkey = PublicKey::from_str("0313a906d2bbb008c3738b7cafcac215b578f66b5a2faabba26d85dc86b2bee854").unwrap();

        assert!(signature.verify(&message[..], &pubkey).is_ok());

    }
}
