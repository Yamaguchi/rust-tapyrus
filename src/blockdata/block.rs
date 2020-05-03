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

//! Bitcoin Block
//!
//! A block is a bundle of transactions with a proof-of-work attached,
//! which commits to an earlier block to form the blockchain. This
//! module describes structures and functions needed to describe
//! these blocks and the blockchain.
//!

use std::io;

use hashes::Hash;
use hash_types::{BlockHash, TxMerkleNode};
use consensus::{encode, Decodable, Encodable};
use blockdata::transaction::Transaction;
use util::hash::{bitcoin_merkle_root, BitcoinHash};
use util::key::PublicKey;
use util::signature::Signature;

/// A block header, which contains all the block's information except
/// the actual transactions
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct BlockHeader {
    /// The protocol version. Should always be 1.
    pub version: u32,
    /// Reference to the previous block in the chain
    pub prev_blockhash: BlockHash,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: TxMerkleNode,
    /// MerkleRoot based on fixing malleability transaction hash
    pub im_merkle_root: TxMerkleNode,
    /// The timestamp of the block, as claimed by the miner
    pub time: u32,
    ///Aggregate public key of tapyrus-signer used to verify block proof. This field is optional and may be present in all blocks.
    pub aggregated_public_key: PublicKeyOpt,
    /// Collection holds a signature for block hash which is consisted of block header without Proof.
    pub proof: Option<Signature>,
}

/// Optional aggregated public key
pub type PublicKeyOpt = Option<PublicKey>;

impl Decodable for PublicKeyOpt {
    #[inline]
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        match Decodable::consensus_decode(&mut d) {
            Ok(pk) => Ok(Some(pk)),
            Err(_) => Ok(None),
        }
    }
}

impl Encodable for PublicKeyOpt {
    #[inline]
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, encode::Error> {
        match *self {
            Some(pk) => pk.consensus_encode(&mut s),
            None => {
                let v = Vec::<u8>::new();
                v.consensus_encode(&mut s)
            }
        }
    }
}

/// A Bitcoin block, which is a collection of transactions with an attached
/// proof of work.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct Block {
    /// The block header
    pub header: BlockHeader,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>
}

impl Block {
    /// check if merkle root of header matches merkle root of the transaction list
    pub fn check_merkle_root (&self) -> bool {
        self.header.merkle_root == self.merkle_root() &&
            self.header.im_merkle_root == self.immutable_merkle_root()
    }

    /// Calculate the transaction merkle root.
    pub fn merkle_root(&self) -> TxMerkleNode {
        let hashes = self.txdata.iter().map(|obj| obj.txid().as_hash());
        bitcoin_merkle_root(hashes).into()
    }

    /// Calculate the immutable transaction merkle root.
    fn immutable_merkle_root(&self) -> TxMerkleNode {
        let hashes = self.txdata.iter().map(|obj| obj.malfix_txid().as_hash());
        bitcoin_merkle_root(hashes).into()
    }
}

impl BitcoinHash<BlockHash> for BlockHeader {
    fn bitcoin_hash(&self) -> BlockHash {
        use consensus::encode::serialize;
        BlockHash::hash(&serialize(self))
    }
}

impl BitcoinHash<BlockHash> for Block {
    fn bitcoin_hash(&self) -> BlockHash {
        self.header.bitcoin_hash()
    }
}

impl_consensus_encoding!(
    BlockHeader,
    version,
    prev_blockhash,
    merkle_root,
    im_merkle_root,
    time,
    aggregated_public_key,
    proof
);
impl_consensus_encoding!(Block, header, txdata);
serde_struct_impl!(
    BlockHeader,
    version,
    prev_blockhash,
    merkle_root,
    im_merkle_root,
    time,
    aggregated_public_key,
    proof);
serde_struct_impl!(Block, header, txdata);

#[cfg(test)]
mod tests {
    use hex::decode as hex_decode;
    use std::str::FromStr;

    use blockdata::block::Block;
    use consensus::encode::{deserialize, serialize};
    use util::key::PublicKey;

    #[test]
    fn block_test() {
        let some_block = hex_decode("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c364243a74762685f916378ce87c5384ad39b594aca206426d9d244ef51d644d2d74d6e4921032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af40f1453cd332262d74edf65f96688724b80a15c852fd50151e4aabc41a0d9560d2cd38f0746c3d9c9e18b236f20e37d0ae1bda457ea029db8a55b20f38143517d00201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000").unwrap();
        let cutoff_block = hex_decode("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c364243a74762685f916378ce87c5384ad39b594aca206426d9d244ef51d644d2d74d6e4921032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac").unwrap();

        let prevhash =
            hex_decode("4ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000").unwrap();
        let merkle =
            hex_decode("bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c").unwrap();
        let pk = PublicKey::from_str(
            "032e58afe51f9ed8ad3cc7897f634d881fdbe49a81564629ded8156bebd2ffd1af",
        )
        .unwrap();
        let sig = deserialize(&hex::decode("f1453cd332262d74edf65f96688724b80a15c852fd50151e4aabc41a0d9560d2cd38f0746c3d9c9e18b236f20e37d0ae1bda457ea029db8a55b20f38143517d0").unwrap()).unwrap();
        let decode: Result<Block, _> = deserialize(&some_block);
        let bad_decode: Result<Block, _> = deserialize(&cutoff_block);

        assert!(decode.is_ok());
        assert!(bad_decode.is_err());
        let real_decode = decode.unwrap();
        assert_eq!(real_decode.header.version, 1);
        assert_eq!(serialize(&real_decode.header.prev_blockhash), prevhash);
        assert_eq!(real_decode.header.merkle_root, real_decode.merkle_root());
        assert_eq!(
            real_decode.header.im_merkle_root,
            real_decode.immutable_merkle_root()
        );
        assert_eq!(serialize(&real_decode.header.merkle_root), merkle);
        assert_eq!(real_decode.header.time, 1231965655);
        assert_eq!(real_decode.header.aggregated_public_key.unwrap(), pk);
        assert_eq!(real_decode.header.proof.unwrap(), sig);
        // [test] TODO: check the transaction data

        assert_eq!(serialize(&real_decode), some_block);
    }

    #[test]
    fn no_aggkey_and_no_proof_block_test() {
        let some_block = hex_decode("010000004ddccd549d28f385ab457e98d1b11ce80bfea2c5ab93015ade4973e400000000bf4473e53794beae34e64fccc471dace6ae544180816f89591894e0f417a914c364243a74762685f916378ce87c5384ad39b594aca206426d9d244ef51d644d2d74d6e4900000201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0804ffff001d026e04ffffffff0100f2052a0100000043410446ef0102d1ec5240f0d061a4246c1bdef63fc3dbab7733052fbbf0ecd8f41fc26bf049ebb4f9527f374280259e7cfa99c48b0e3f39c51347a19a5819651503a5ac00000000010000000321f75f3139a013f50f315b23b0c9a2b6eac31e2bec98e5891c924664889942260000000049483045022100cb2c6b346a978ab8c61b18b5e9397755cbd17d6eb2fe0083ef32e067fa6c785a02206ce44e613f31d9a6b0517e46f3db1576e9812cc98d159bfdaf759a5014081b5c01ffffffff79cda0945903627c3da1f85fc95d0b8ee3e76ae0cfdc9a65d09744b1f8fc85430000000049483045022047957cdd957cfd0becd642f6b84d82f49b6cb4c51a91f49246908af7c3cfdf4a022100e96b46621f1bffcf5ea5982f88cef651e9354f5791602369bf5a82a6cd61a62501fffffffffe09f5fe3ffbf5ee97a54eb5e5069e9da6b4856ee86fc52938c2f979b0f38e82000000004847304402204165be9a4cbab8049e1af9723b96199bfd3e85f44c6b4c0177e3962686b26073022028f638da23fc003760861ad481ead4099312c60030d4cb57820ce4d33812a5ce01ffffffff01009d966b01000000434104ea1feff861b51fe3f5f8a3b12d0f4712db80e919548a80839fc47c6a21e66d957e9c5d8cd108c7a2d2324bad71f9904ac0ae7336507d785b17a2c115e427a32fac00000000").unwrap();
        let decode: Result<Block, _> = deserialize(&some_block);

        assert!(decode.is_ok());
        let real_decode = decode.unwrap();
        assert!(real_decode.header.aggregated_public_key.is_none());
        assert!(real_decode.header.proof.is_none());
    }
}
