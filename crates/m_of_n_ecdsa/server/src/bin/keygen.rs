use alloy_primitives::keccak256;
use clap::Parser;
use m_of_n_ecdsa_server::m_of_n_ecdsa_sdk_vm_config;
use signature_prover_lib::{init_logging, keygen, BuildAndKeygenArgs};

pub fn main() -> eyre::Result<()> {
    let args = BuildAndKeygenArgs::parse();
    init_logging(args.log_format);
    let elf = args.guest.build()?;

    let pk_data = keygen(elf, m_of_n_ecdsa_sdk_vm_config(), &args.keygen)?;

    let vk: Vec<u8> = pk_data.onchain_vk.write()?;
    tracing::info!(vk = %hex::encode(&vk), "verification key");

    let vk_hash = keccak256(&vk);
    tracing::info!(vk_hash = %hex::encode(vk_hash), "verification key hash");

    pk_data.write(args.keygen.data_dir)
}
