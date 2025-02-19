use alloy_primitives::{Address, B256, U256};
use alloy_sol_types::SolValue;
use m_of_n_ecdsa_guest::{MOfNEcdsaAuthData, MOfNEcdsaInput, MOfNEcdsaKeyData};
use signature_prover_server::{AuthInputs, AuthInputsDecoder};

#[derive(Debug, thiserror::Error)]
pub enum MOfNEcdsaInputDecodeError {
    #[error("data decode failed: {0}")]
    DataDecodeFailed(eyre::Report),
    #[error("invalid signatures")]
    InvalidSignatures,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct MOfNEcdsaInputDecoder {}

impl AuthInputsDecoder for MOfNEcdsaInputDecoder {
    type Error = MOfNEcdsaInputDecodeError;

    type ServerAuthInput = MOfNEcdsaInput;

    fn decode(
        &self,
        auth_inputs: AuthInputs,
        msg_hash: B256,
    ) -> Result<Self::ServerAuthInput, Self::Error> {
        let (codehash, m, signers_list) =
            <(B256, U256, Vec<Address>)>::abi_decode_params(&auth_inputs.key_data[1..], true)
                .map_err(|err| MOfNEcdsaInputDecodeError::DataDecodeFailed(err.into()))?;

        let mut signatures = Vec::new();
        for chunk in auth_inputs.auth_data.chunks(65) {
            let sig_bytes: [u8; 65] = chunk
                .try_into()
                .map_err(|_| MOfNEcdsaInputDecodeError::InvalidSignatures)?;
            signatures.push(sig_bytes.into());
        }

        Ok(MOfNEcdsaInput {
            msg_hash,
            key_data: MOfNEcdsaKeyData {
                codehash,
                m: m.as_limbs()[0] as u32,
                eoa_addrs: signers_list,
            },
            auth_data: MOfNEcdsaAuthData { signatures },
        })
    }
}

#[cfg(test)]
mod tests {
    use alloy_primitives::{keccak256, Address, Bytes, FixedBytes};
    use m_of_n_ecdsa_guest::{MOfNEcdsaAuthData, MOfNEcdsaInput, MOfNEcdsaKeyData};
    use signature_prover_guest::KeyData;
    use signature_prover_server::{AuthInputs, AuthInputsDecoder};

    use crate::MOfNEcdsaInputDecodeError;

    use super::MOfNEcdsaInputDecoder;

    fn generate_1_of_1_ecdsa_input() -> MOfNEcdsaInput {
        let key_data = MOfNEcdsaKeyData {
            codehash: FixedBytes::random(),
            m: 1,
            eoa_addrs: vec![Address::random()],
        };
        let auth_data = MOfNEcdsaAuthData {
            signatures: vec![FixedBytes::random()],
        };

        let message = Bytes::from_static(b"message");
        let msg_hash = keccak256(&message);

        MOfNEcdsaInput {
            msg_hash,
            key_data,
            auth_data,
        }
    }

    #[test]
    fn test_decode_successful() {
        let input = generate_1_of_1_ecdsa_input();
        let auth_inputs = AuthInputs {
            key_data: input.key_data.encode(),
            auth_data: Bytes::from(input.auth_data.signatures.concat()),
        };

        let decoder = MOfNEcdsaInputDecoder::default();
        let input = decoder.decode(auth_inputs, input.msg_hash).unwrap();

        assert_eq!(input.msg_hash, input.msg_hash);

        assert_eq!(input.key_data.codehash, input.key_data.codehash);
        assert_eq!(input.key_data.m, input.key_data.m);
        assert_eq!(input.key_data.eoa_addrs, input.key_data.eoa_addrs);

        assert_eq!(input.auth_data.signatures, input.auth_data.signatures);
    }

    #[test]
    fn test_decode_tampered_data() {
        let input = generate_1_of_1_ecdsa_input();

        let decoder = MOfNEcdsaInputDecoder::default();

        let auth_inputs = AuthInputs {
            key_data: input.key_data.encode(),
            auth_data: Bytes::from(input.auth_data.signatures.concat()),
        };

        let mut auth_inputs_invalid_key_data = auth_inputs.clone();
        auth_inputs_invalid_key_data.key_data =
            auth_inputs_invalid_key_data.key_data[1..].to_vec().into();
        let res = decoder.decode(auth_inputs_invalid_key_data, input.msg_hash);
        assert!(matches!(
            res,
            Err(MOfNEcdsaInputDecodeError::DataDecodeFailed(_))
        ));

        let mut auth_inputs_invalid_auth_data = auth_inputs.clone();
        auth_inputs_invalid_auth_data.auth_data =
            auth_inputs_invalid_auth_data.auth_data[1..].to_vec().into();
        let res = decoder.decode(auth_inputs_invalid_auth_data, input.msg_hash);
        assert!(matches!(
            res,
            Err(MOfNEcdsaInputDecodeError::InvalidSignatures)
        ));
    }
}
