use alloy_primitives::{address, hex, Address, Bytes, FixedBytes, B256, U256};
use jsonrpsee::{core::client::ClientT, http_client::HttpClientBuilder, rpc_params};
use m_of_n_ecdsa_guest::MOfNEcdsaKeyData;
use m_of_n_ecdsa_server::test_utils::ecdsa_sign;
use m_of_n_ecdsa_server::test_utils::{CODEHASH, M_OF_N_ECDSA_VKEY};
use signature_prover_guest::KeyData;
use signature_prover_server::keystore_types::{KeystoreAccount, UpdateTransaction};
use signature_prover_server::{AuthInputs, AuthRequestStatus, SponsoredAuthInputs};

fn construct_auth_inputs(
    codehash: B256,
    signatures: Vec<FixedBytes<65>>,
    eoa_addrs: Vec<Address>,
) -> AuthInputs {
    let key_data = MOfNEcdsaKeyData {
        codehash,
        m: signatures.len() as u32,
        eoa_addrs,
    }
    .encode();
    AuthInputs {
        key_data,
        auth_data: Bytes::from(signatures.concat()),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client
    let client = HttpClientBuilder::default()
        .request_timeout(std::time::Duration::from_secs(120))
        .build("http://127.0.0.1:8000")?;

    let keystore_address = B256::random();
    let pk = hex!("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80");

    let eoa_addrs = [
        // Anvil EOA 0
        address!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266"),
    ]
    .to_vec();

    let data_hash = MOfNEcdsaKeyData {
        codehash: *CODEHASH,
        m: 1,
        eoa_addrs: eoa_addrs.clone(),
    }
    .data_hash();
    // use for both user and sponsor
    let accnt = KeystoreAccount::with_keystore_address(
        keystore_address,
        data_hash,
        M_OF_N_ECDSA_VKEY.clone(),
    );
    let update_tx = UpdateTransaction::new(
        false,
        U256::from(0),
        Some(U256::from(100)).into(),
        None.into(),
        Bytes::from_static(&[1u8; 22]),
        Bytes::from_static(&[1u8; 22]),
        accnt.clone(),
        Bytes::default(),
        Some(accnt).into(),
        Bytes::default(),
    );
    let user_msg_hash = update_tx.user_msg_hash();
    let sponsor_msg_hash = update_tx.sponsor_msg_hash();
    let user_sig = ecdsa_sign(pk.into(), user_msg_hash);
    let sponsor_sig = ecdsa_sign(pk.into(), sponsor_msg_hash.unwrap());

    let raw_tx = update_tx.into_tx_bytes();

    let sponsor_signatures: Vec<FixedBytes<65>> = vec![sponsor_sig];
    let sponsor_eoa_addrs = eoa_addrs.clone();
    let user_signatures: Vec<FixedBytes<65>> = vec![user_sig];
    let user_eoa_addrs = eoa_addrs.clone();

    // Create sponsor auth inputs
    let sponsor_auth_inputs = SponsoredAuthInputs::ProveSponsored {
        user_auth_inputs: construct_auth_inputs(*CODEHASH, user_signatures, user_eoa_addrs),
        sponsor_auth_inputs: construct_auth_inputs(
            *CODEHASH,
            sponsor_signatures,
            sponsor_eoa_addrs,
        ),
    };

    // Send authentication request
    let request_hash: B256 = client
        .request(
            "keystore_authenticateSponsoredTransaction",
            rpc_params![raw_tx, sponsor_auth_inputs],
        )
        .await?;

    println!(
        "Transaction sent! Request hash: 0x{}",
        hex::encode(request_hash)
    );

    // Poll for status for 10 minutes
    for _ in 0..10 {
        let status = client
            .request::<Option<AuthRequestStatus>, _>(
                "keystore_getSponsoredAuthenticationStatus",
                rpc_params![request_hash],
            )
            .await?;

        println!("Status: {:?}", status);
        tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
    }

    Ok(())
}
