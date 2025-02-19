use alloy_primitives::{address, hex, keccak256, Address, Bytes, FixedBytes, B256};
use alloy_signer::SignerSync;
use alloy_signer_local::PrivateKeySigner;
use lazy_static::lazy_static;
use m_of_n_ecdsa_guest::MOfNEcdsaKeyData;
use signature_prover_guest::KeyData;
use signature_prover_server::keystore_types::KeystoreAccount;

lazy_static! {
    /// codehash uniquely identifies the logic embedded within the consumer contract
    pub static ref CODEHASH: B256 = B256::from_slice(&hex!("a1b20564cd6cc6410266a716c9654406a15e822d4dc89c4127288da925d5c225"));

    /// Verifying key for the m-of-n ECDSA OpenVM program
    pub static ref M_OF_N_ECDSA_VKEY: Bytes = Bytes::from_static(&hex!("01010000001001000100010100000100000000000000000000000000000000009171ded76cb8d446b69cb901fe413fe380886240549feb11014fec000a7eb1280750a550988ceaef9a37f6794af0d9bf472445bc9dfacf89b9f4a6130c2b0eb42ef05dfd54c6d765973c1b3e0c15885e1307bedc893a3474103a065e7a032d04078f64fde979db4eea6692dbde7d161c3e6c3ae99f2e7cf9c58229f8d1a5bb97056fb20596873754a862cbe247b25315399d7be7a8bfe72942564c469d6a95e141a2f3c0bb526ad5ded741e9c10d6920cd28a10f108b0d1f2b22688b67a32c4055f6d42ed1d1c3eb767c513d8aa832c470b29a9dc7afb33fdcfeda198b820f724d13a24c6d1123d95b1124cf08c4aaf9531dd819011b9a13b6151d5ab83225fe4517"));

    pub static ref SPONSOR_EOA_ADDRESS: Address = address!("D7548a3ED8c51FA30D26ff2D7Db5C33d27fd48f2");

    pub static ref SPONSOR_DATA: Bytes = MOfNEcdsaKeyData {
        codehash: *CODEHASH,  // codehash
        m: 0u32, // m
        eoa_addrs: vec![*SPONSOR_EOA_ADDRESS]  // signers_list
    }.encode();

    pub static ref SPONSOR_DATA_HASH: B256 = keccak256(SPONSOR_DATA.clone());

    pub static ref SPONSOR_ACCOUNT: KeystoreAccount = KeystoreAccount::with_salt(
        FixedBytes::new([1u8; 32]),
        *SPONSOR_DATA_HASH,
        Bytes::from_static(&M_OF_N_ECDSA_VKEY),
    );
}

/// Signs a msg_hash with a private key and returns a signature with recovery id
pub fn ecdsa_sign(pk: B256, msg_hash: B256) -> FixedBytes<65> {
    let signer = PrivateKeySigner::from_bytes(&pk).unwrap();
    let signature = signer.sign_hash_sync(&msg_hash).unwrap();
    signature.as_bytes().as_slice().try_into().unwrap()
}
