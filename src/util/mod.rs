// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//
// Changes for rust-tapyrus is licensed as below.
// Copyright (c) 2019 Chaintope Inc.
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//

//! Utility functions
//!
//! Functions needed by all parts of the Bitcoin library

pub mod address;
pub mod amount;
pub mod base58;
pub mod bip143;
pub mod bip158;
pub mod bip32;
pub mod contracthash;
pub mod hash;
pub mod key;
pub mod merkleblock;
pub mod misc;
pub mod psbt;
pub mod uint;
pub mod signature;
pub mod prime;
pub mod rfc6979;

pub(crate) mod endian;

use std::{error, fmt};

use consensus::encode;
use network;

/// A trait which allows numbers to act as fixed-size bit arrays
pub trait BitArray {
    /// Is bit set?
    fn bit(&self, idx: usize) -> bool;

    /// Returns an array which is just the bits from start to end
    fn bit_slice(&self, start: usize, end: usize) -> Self;

    /// Bitwise and with `n` ones
    fn mask(&self, n: usize) -> Self;

    /// Trailing zeros
    fn trailing_zeros(&self) -> usize;

    /// Create all-zeros value
    fn zero() -> Self;

    /// Create value representing one
    fn one() -> Self;
}

/// A general error code, other errors should implement conversions to/from this
/// if appropriate.
#[derive(Debug)]
pub enum Error {
    /// Encoding error
    Encode(encode::Error),
    /// Network error
    Network(network::Error),
    /// Signature error
    Signature(signature::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Encode(ref e) => fmt::Display::fmt(e, f),
            Error::Network(ref e) => fmt::Display::fmt(e, f),
            Error::Signature(ref e) => fmt::Display::fmt(e, f),
        }
    }
}

#[allow(deprecated)]
impl error::Error for Error {
    fn cause(&self) -> Option<&error::Error> {
        match *self {
            Error::Encode(ref e) => Some(e),
            Error::Network(ref e) => Some(e),
            Error::Signature(ref e) => Some(e),
        }
    }

    fn description(&self) -> &str {
        "description() is deprecated; use Display"
    }
}

#[doc(hidden)]
impl From<encode::Error> for Error {
    fn from(e: encode::Error) -> Error {
        Error::Encode(e)
    }
}

#[doc(hidden)]
impl From<network::Error> for Error {
    fn from(e: network::Error) -> Error {
        Error::Network(e)
    }
}
