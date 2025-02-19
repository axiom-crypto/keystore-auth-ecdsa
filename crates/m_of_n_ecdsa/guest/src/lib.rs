use std::collections::btree_set::BTreeSet;

use alloy_primitives::{bytes, normalize_v, Address, Bytes, FixedBytes, B256, B512, U256};
use alloy_sol_types::SolValue;
use revm_precompile::secp256k1::ecrecover;
use serde::{Deserialize, Serialize};
use signature_prover_guest::{KeyData, SignatureProverInput};

pub type MOfNEcdsaInput = SignatureProverInput<MOfNEcdsaKeyData, MOfNEcdsaAuthData>;

#[derive(Clone, Serialize, Deserialize)]
pub struct MOfNEcdsaKeyData {
    pub codehash: B256,
    pub m: u32,
    pub eoa_addrs: Vec<Address>,
}

impl KeyData for MOfNEcdsaKeyData {
    /// ABI encoding of the data hash data: abi.encodePacked(0x00, abi.encode(codehash, m, eoa_addrs))
    fn encode(&self) -> Bytes {
        let inner_encoded = (
            self.codehash,
            U256::from(self.m),
            &self.eoa_addrs as &[Address],
        )
            .abi_encode_params();
        let result = (bytes!("0x00"), inner_encoded).abi_encode_packed();
        Bytes::from(result)
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MOfNEcdsaAuthData {
    pub signatures: Vec<FixedBytes<65>>,
}

/// Circuit statement:
/// * keccak256(abi.encodePacked(0x00, abi.encode(codehash, m, eoa_addrs))) == data_hash
/// * there are [ECDSA signatures] for msg_hash which verifies against [pub_keys]
/// * [eoa_addrs] corresponds to [pub_keys]
pub fn verify(inputs: MOfNEcdsaInput) {
    assert_eq!(
        inputs.auth_data.signatures.len(),
        inputs.key_data.m as usize
    );

    // Verify the signatures are valid and that the signature EOAs are distinct
    let mut signature_eoa_set: BTreeSet<Address> = BTreeSet::new();
    for full_sig in inputs.auth_data.signatures.iter() {
        let sig = B512::from_slice(&full_sig.0[..64]);
        let rec_id = normalize_v(full_sig.0[64] as u64).expect("invalid parity") as u8;
        let signer = ecrecover(&sig, rec_id, &inputs.msg_hash).expect("ecrecover failed");
        let eth_addr = Address::from_slice(&signer.0[12..]);

        // Check that the recovered EOA address is in `eoa_addrs`
        assert!(inputs.key_data.eoa_addrs.contains(&eth_addr));
        signature_eoa_set.insert(eth_addr);
    }
    // Validate that the number of unique recovered EOA addresses equals m
    assert_eq!(signature_eoa_set.len() as u32, inputs.key_data.m);
}
