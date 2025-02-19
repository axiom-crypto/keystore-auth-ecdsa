use std::{path::PathBuf, str::FromStr};

use alloy_primitives::{Address, FixedBytes, B256};
use hex_literal::hex;
use m_of_n_ecdsa_guest::{MOfNEcdsaAuthData, MOfNEcdsaInput, MOfNEcdsaKeyData};
use once_cell::sync::Lazy;
use openvm_keccak256_guest::keccak256;
use signature_prover_guest::KeyData;
use signature_prover_lib::test_utils::SignatureProverTester;

use crate::{m_of_n_ecdsa_sdk_vm_config, test_utils::ecdsa_sign, test_utils::CODEHASH};

const CHAIN_ID: u64 = 999999999;

pub fn to_hi_lo_le(x: [u8; 32]) -> ([u8; 32], [u8; 32]) {
    let mut x = x;
    x.reverse();
    let mut hi = [0u8; 32];
    let mut lo = [0u8; 32];
    hi[0..16].copy_from_slice(&x[16..32]);
    lo[0..16].copy_from_slice(&x[0..16]);
    (hi, lo)
}

pub static ANVIL_ACCOUNTS: Lazy<Vec<([u8; 32], Address)>> = Lazy::new(|| {
    vec![
        (
            hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
            Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap(),
        ),
        (
            hex!("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
            Address::from_str("0x70997970c51812dc3a010c7d01b50e0d17dc79c8").unwrap(),
        ),
        (
            hex!("5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a"),
            Address::from_str("0x3c44cdddb6a900fa2b585dd299e03d12fa4293bc").unwrap(),
        ),
    ]
});

fn build_m_of_n_ecdsa_test_inputs(
    m: u32,
    private_keys: Vec<[u8; 32]>,
    eoa_addrs: Vec<Address>,
) -> MOfNEcdsaInput {
    let mut private_keys = private_keys.clone();
    private_keys.truncate(m as usize);

    let codehash = *CODEHASH;

    let msg = b"message";
    let msg_hash: B256 = keccak256(msg).into();
    let signatures: Vec<_> = private_keys
        .iter()
        .map(|k| ecdsa_sign(k.into(), msg_hash))
        .collect();

    MOfNEcdsaInput {
        msg_hash,
        key_data: MOfNEcdsaKeyData {
            codehash,
            m,
            eoa_addrs,
        },
        auth_data: MOfNEcdsaAuthData { signatures },
    }
}

fn guest_manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("guest")
}

fn tester() -> SignatureProverTester {
    let vm_config = m_of_n_ecdsa_sdk_vm_config();
    SignatureProverTester::new(
        guest_manifest_dir(),
        "m-of-n-ecdsa-guest".to_owned(),
        vm_config,
    )
}

fn default_kzg_params_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Could not find home directory")
        .join(".openvm")
        .join("params")
}

#[test]
fn test_m_of_n_ecdsa_guest() {
    let m = 2;

    let (anvil_private_keys, anvil_eoa_addrs): (Vec<[u8; 32]>, Vec<Address>) =
        ANVIL_ACCOUNTS.clone().into_iter().unzip();

    let inputs = build_m_of_n_ecdsa_test_inputs(m, anvil_private_keys, anvil_eoa_addrs);
    let tester = tester();
    tester.test_execute(inputs).unwrap();
}

#[test]
fn test_user_public_values() {
    let m = 2;

    let (anvil_private_keys, anvil_eoa_addrs): (Vec<[u8; 32]>, Vec<Address>) =
        ANVIL_ACCOUNTS.clone().into_iter().unzip();

    let msg = b"message";
    let msg_hash: B256 = keccak256(msg).into();

    // Default Anvil private keys
    let mut anvil_private_keys = anvil_private_keys.clone();
    anvil_private_keys.truncate(m as usize);

    let codehash = *CODEHASH;
    let data_hash = MOfNEcdsaKeyData {
        codehash,
        m,
        eoa_addrs: anvil_eoa_addrs.clone(),
    }
    .data_hash();
    println!("data_hash: {:?}", data_hash);
    println!("msg_hash: {:?}", msg_hash);

    let input = build_m_of_n_ecdsa_test_inputs(m, anvil_private_keys, anvil_eoa_addrs);

    let tester = tester();
    let public_values = tester.test_execute(input).unwrap();

    let expected_output = [data_hash, msg_hash]
        .concat()
        .into_iter()
        .flat_map(|x| x.to_le_bytes())
        .collect::<Vec<_>>();

    println!("pv_proof.public_values: {}", hex::encode(&public_values));
    println!("expected_output: {}", hex::encode(&expected_output));
    assert_eq!(public_values, expected_output);
}

// RUST_MIN_STACK=8388608 cargo t test_final_proof_values --release -- --ignored
#[test]
#[ignore = "Integration test requires >32GB RAM"]
fn test_final_proof_values() {
    let m = 2;

    let (anvil_private_keys, anvil_eoa_addrs): (Vec<[u8; 32]>, Vec<Address>) =
        ANVIL_ACCOUNTS.clone().into_iter().unzip();

    let inputs = build_m_of_n_ecdsa_test_inputs(m, anvil_private_keys, anvil_eoa_addrs.clone());
    let tester = tester();

    let evm_proof = tester.test_evm(inputs, default_kzg_params_dir()).unwrap();

    let msg = b"message";
    let codehash = *CODEHASH;

    let data_hash = MOfNEcdsaKeyData {
        codehash,
        m,
        eoa_addrs: anvil_eoa_addrs,
    }
    .data_hash();
    let data_hash_hi_lo = to_hi_lo_le(data_hash.into());
    let msg_hash = keccak256(msg);
    let msg_hash_hi_lo = to_hi_lo_le(msg_hash);
    let pvs_cmp = [
        data_hash_hi_lo.0,
        data_hash_hi_lo.1,
        msg_hash_hi_lo.0,
        msg_hash_hi_lo.1,
    ];

    let pvs = evm_proof.instances[0].clone();
    let onchain_pvs = pvs[pvs.len() - 4..]
        .iter()
        .map(|x| x.to_bytes())
        .collect::<Vec<_>>();

    for (i, pv) in onchain_pvs.iter().enumerate() {
        assert_eq!(*pv, pvs_cmp[i]);
    }
}

#[test]
fn test_abi_encoding() {
    let codehash = *CODEHASH;
    let (_, anvil_eoa_addrs): (Vec<[u8; 32]>, Vec<Address>) =
        ANVIL_ACCOUNTS.clone().into_iter().unzip();
    let encoded = MOfNEcdsaKeyData {
        codehash,
        m: 2,
        eoa_addrs: anvil_eoa_addrs,
    }
    .data_hash();
    let reference =
        B256::from_str("0x99ccd0302bd0f77ca5f308fa7bb1059469f63f8abea02732a70ae5612615ee3c")
            .unwrap();
    assert_eq!(encoded, reference);
}

#[test]
fn test_ecdsa_sign_recovery_id_eth() {
    let (m, msg_hash, codehash, signatures, eoa_addrs) = get_recovery_id_test_params();
    let recovery_id = signatures[0][64];
    run_recovery_id_test(m, msg_hash, codehash, signatures, eoa_addrs, recovery_id);
}

#[test]
fn test_ecdsa_sign_recovery_id_ecdsa_std() {
    let (m, msg_hash, codehash, signatures, eoa_addrs) = get_recovery_id_test_params();
    let recovery_id = signatures[0][64];
    let recovery_id = recovery_id - 27;
    run_recovery_id_test(m, msg_hash, codehash, signatures, eoa_addrs, recovery_id);
}

#[test]
fn test_ecdsa_sign_recovery_id_eip155() {
    let (m, msg_hash, codehash, signatures, eoa_addrs) = get_recovery_id_test_params();
    let recovery_id = signatures[0][64];
    let recovery_id = ((35 + 2 * CHAIN_ID + recovery_id as u64) % 2) as u8;
    run_recovery_id_test(m, msg_hash, codehash, signatures, eoa_addrs, recovery_id);
}

#[test]
#[should_panic]
fn test_m_of_n_ecdsa_invalid_num_signatures_guest() {
    let m = 2;

    let (mut anvil_private_keys, anvil_eoa_addrs): (Vec<[u8; 32]>, Vec<Address>) =
        ANVIL_ACCOUNTS.clone().into_iter().unzip();

    anvil_private_keys.truncate(1);

    let inputs = build_m_of_n_ecdsa_test_inputs(m, anvil_private_keys, anvil_eoa_addrs);

    let tester = tester();
    tester.test_execute(inputs).unwrap();
}

#[test]
#[should_panic]
fn test_m_of_n_ecdsa_private_key_does_not_match_eoa_guest() {
    let m = 1;

    // Default Anvil private keys
    let invalid_private_keys = [
        // Anvil private key 0 (modified)
        hex!("ee0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
    ]
    .to_vec();

    let (_, anvil_eoa_addrs): (Vec<[u8; 32]>, Vec<Address>) =
        ANVIL_ACCOUNTS.clone().into_iter().unzip();

    let inputs = build_m_of_n_ecdsa_test_inputs(m, invalid_private_keys, anvil_eoa_addrs);

    let tester = tester();
    tester.test_execute(inputs).unwrap();
}

#[test]
#[should_panic]
fn test_m_of_n_ecdsa_duplicate_signature_guest() {
    let m = 3;

    // Default Anvil private keys
    let anvil_private_keys = [
        // Anvil private key 0
        hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
        // Anvil private key 1
        hex!("59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d"),
        // Anvil private key 0 (duplicate)
        hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"),
    ]
    .to_vec();

    let (_, anvil_eoa_addrs): (Vec<[u8; 32]>, Vec<Address>) =
        ANVIL_ACCOUNTS.clone().into_iter().unzip();

    let inputs = build_m_of_n_ecdsa_test_inputs(m, anvil_private_keys, anvil_eoa_addrs);

    let tester = tester();
    tester.test_execute(inputs).unwrap();
}

#[allow(clippy::type_complexity)]
fn get_recovery_id_test_params() -> (u32, B256, B256, Vec<FixedBytes<65>>, Vec<Address>) {
    let m = 1;

    let (mut anvil_private_keys, anvil_eoa_addrs): (Vec<[u8; 32]>, Vec<Address>) =
        ANVIL_ACCOUNTS.clone().into_iter().unzip();
    anvil_private_keys.truncate(m as usize);

    let msg = b"message";
    let msg_hash: B256 = keccak256(msg).into();
    let codehash = *CODEHASH;

    let signatures = anvil_private_keys
        .iter()
        .map(|k| ecdsa_sign(k.into(), msg_hash))
        .collect::<Vec<_>>();

    (m, msg_hash, codehash, signatures, anvil_eoa_addrs)
}

#[allow(clippy::too_many_arguments)]
fn run_recovery_id_test(
    m: u32,
    msg_hash: B256,
    codehash: B256,
    signatures: Vec<FixedBytes<65>>,
    eoa_addrs: Vec<Address>,
    recovery_id: u8,
) {
    let mut signatures = signatures;
    signatures[0][64] = recovery_id;
    let input = MOfNEcdsaInput {
        msg_hash,
        key_data: MOfNEcdsaKeyData {
            codehash,
            m,
            eoa_addrs,
        },
        auth_data: MOfNEcdsaAuthData { signatures },
    };

    let tester = tester();
    tester.test_execute(input).unwrap();
}
