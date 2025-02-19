use openvm_algebra_circuit::ModularExtension;
use openvm_circuit::arch::SystemConfig;
use openvm_ecc_circuit::{WeierstrassExtension, SECP256K1_CONFIG};
use openvm_ecc_guest::k256::{SECP256K1_MODULUS, SECP256K1_ORDER};
use openvm_sdk::config::{SdkSystemConfig, SdkVmConfig};
use signature_prover_lib::NUM_USER_PUBLIC_VALUES_BYTES;

pub fn m_of_n_ecdsa_sdk_vm_config() -> SdkVmConfig {
    SdkVmConfig::builder()
        .system(SdkSystemConfig {
            config: SystemConfig::default()
                .with_continuations()
                .with_public_values(NUM_USER_PUBLIC_VALUES_BYTES),
        })
        .rv32i(Default::default())
        .rv32m(Default::default())
        .io(Default::default())
        .keccak(Default::default())
        .modular(ModularExtension::new(vec![
            SECP256K1_MODULUS.clone(),
            SECP256K1_ORDER.clone(),
        ]))
        .ecc(WeierstrassExtension::new(vec![SECP256K1_CONFIG.clone()]))
        .build()
}
