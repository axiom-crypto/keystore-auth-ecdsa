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
    pub static ref M_OF_N_ECDSA_VKEY: Bytes = Bytes::from_static(&hex!("010100000010010001000101000001000000000000000000000000000000000012cc28286481bc0f065cf8bf80bdde96699ee78fdf81b0411f235567df5376030750a550988ceaef9a37f6794af0d9bf472445bc9dfacf89b9f4a6130c2b0eb42e33dd7c9a722bac01dd9a3dc080d8a91eed1eee79c126496fce4ec88a6f2c4d0d8f64fde979db4eea6692dbde7d161c3e6c3ae99f2e7cf9c58229f8d1a5bb97056fb20596873754a862cbe247b25315399d7be7a8bfe72942564c469d6a95e14122965713fa56d1e33b08b06b7ed3049b2026d854b3f402acccc79c220f89280024e07d4b3dab4b3cde1622d7bdb447e9cbafc72820ee19e78a0753a88080605713a24c6d1123d95b1124cf08c4aaf9531dd819011b9a13b6151d5ab83225fe4517"));

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
