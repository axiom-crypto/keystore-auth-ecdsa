use alloy_primitives::keccak256;
use clap::Parser;
use m_of_n_ecdsa_server::{MOfNEcdsaInputDecoder, MOfNEcdsaValidator};
use signature_prover_lib::init_logging;
use signature_prover_server::{
    load_server_config, validator::SignatureProverValidator, ServerArgs, SignatureProverServer,
};

#[tokio::main]
pub async fn main() -> eyre::Result<()> {
    // Start the signature prover server
    let args = ServerArgs::parse();
    init_logging(args.log_format);

    let (vkey, sponsor) = load_server_config(&args.config_path)?;
    let vkey_hash = keccak256(&vkey);
    tracing::info!("vkey_hash: 0x{}", hex::encode(vkey_hash));

    let m_of_n_ecdsa_validator = MOfNEcdsaValidator::default();
    let m_of_n_ecdsa_input_decoder = MOfNEcdsaInputDecoder::default();

    let signature_prover_validator = SignatureProverValidator::new(
        m_of_n_ecdsa_input_decoder,
        m_of_n_ecdsa_validator,
        vkey,
        sponsor.clone(),
    );

    let server = SignatureProverServer::initialize(
        m_of_n_ecdsa_input_decoder,
        signature_prover_validator,
        &args,
        sponsor,
    );
    let _handle = server.start(&args).await?;

    // Keep the server running
    tokio::signal::ctrl_c().await?;
    Ok(())
}
