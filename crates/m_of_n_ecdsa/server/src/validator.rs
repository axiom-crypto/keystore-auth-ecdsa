use std::collections::BTreeSet;

use alloy_primitives::{Address, Signature};
use m_of_n_ecdsa_guest::MOfNEcdsaInput;
use signature_prover_server::validator::SignatureProverInputValidator;

#[derive(thiserror::Error, Debug)]
pub enum MOfNEcdsaValidationError {
    #[error("N less than M")]
    NLessThanM,

    #[error("Signature does not verify")]
    InvalidSignature,

    #[error("Signature not from authorized EOA addresses")]
    UnauthorizedSigner,

    #[error("duplicate signature detected")]
    DuplicateSignature,
}

#[derive(Clone, Debug, Default)]
pub struct MOfNEcdsaValidator {}

impl SignatureProverInputValidator for MOfNEcdsaValidator {
    type Error = MOfNEcdsaValidationError;

    type ServerAuthInput = MOfNEcdsaInput;

    fn validate(&self, input: Self::ServerAuthInput) -> Result<(), Self::Error> {
        let m = input.auth_data.signatures.len();

        if m > input.key_data.eoa_addrs.len() {
            return Err(MOfNEcdsaValidationError::NLessThanM);
        }

        let mut signature_eoa_set: BTreeSet<Address> = BTreeSet::new();
        for sig in input.auth_data.signatures {
            let sig = Signature::try_from(sig.0.as_ref())
                .map_err(|_| MOfNEcdsaValidationError::InvalidSignature)?;

            let recovered_addr = sig
                .recover_address_from_prehash(&input.msg_hash)
                .map_err(|_| MOfNEcdsaValidationError::InvalidSignature)?;

            if !input.key_data.eoa_addrs.contains(&recovered_addr) {
                return Err(MOfNEcdsaValidationError::UnauthorizedSigner);
            }

            signature_eoa_set.insert(recovered_addr);
        }
        if signature_eoa_set.len() as u32 != input.key_data.m {
            return Err(MOfNEcdsaValidationError::DuplicateSignature);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use alloy_primitives::{hex, keccak256, Address, FixedBytes, B256};
    use lazy_static::lazy_static;
    use m_of_n_ecdsa_guest::{MOfNEcdsaAuthData, MOfNEcdsaInput, MOfNEcdsaKeyData};
    use signature_prover_server::validator::SignatureProverInputValidator;

    use crate::{test_utils::ecdsa_sign, MOfNEcdsaValidationError};

    use super::MOfNEcdsaValidator;

    lazy_static! {
        static ref ECDSA_INPUT: MOfNEcdsaInput = generate_1_of_1_ecdsa_input();
        static ref VALIDATOR: MOfNEcdsaValidator = MOfNEcdsaValidator::default();
    }

    fn generate_1_of_1_ecdsa_input() -> MOfNEcdsaInput {
        let (pk, eoa_addr) = (
            B256::from_str("ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80")
                .unwrap(),
            Address::from(hex!("f39fd6e51aad88f6f4ce6ab8827279cfffb92266")),
        );
        let codehash = B256::random();

        let msg_hash = keccak256(b"user_message");
        let sig = ecdsa_sign(pk, msg_hash);

        MOfNEcdsaInput {
            key_data: MOfNEcdsaKeyData {
                codehash,
                m: 1,
                eoa_addrs: vec![eoa_addr],
            },
            auth_data: MOfNEcdsaAuthData {
                signatures: vec![sig],
            },
            msg_hash,
        }
    }

    #[test]
    fn test_successful_validation() -> eyre::Result<()> {
        let sponsor_input = ECDSA_INPUT.clone();
        assert!(VALIDATOR.validate(sponsor_input).is_ok());
        Ok(())
    }

    #[test]
    fn test_n_less_than_m() -> eyre::Result<()> {
        let mut sponsor_input = ECDSA_INPUT.clone();
        sponsor_input
            .auth_data
            .signatures
            .push(ecdsa_sign(B256::random(), sponsor_input.msg_hash));

        matches!(
            VALIDATOR.validate(sponsor_input),
            Err(MOfNEcdsaValidationError::NLessThanM)
        );

        Ok(())
    }

    #[test]
    fn test_invalid_signature() -> eyre::Result<()> {
        let mut sponsor_input = ECDSA_INPUT.clone();
        sponsor_input.auth_data.signatures = vec![FixedBytes::<65>::random()];
        matches!(
            VALIDATOR.validate(sponsor_input),
            Err(MOfNEcdsaValidationError::InvalidSignature)
        );

        Ok(())
    }

    #[test]
    fn test_unauthorized_signer() -> eyre::Result<()> {
        let mut sponsor_input = ECDSA_INPUT.clone();

        let sig = ecdsa_sign(B256::random(), sponsor_input.msg_hash);
        sponsor_input.auth_data.signatures = vec![sig];
        matches!(
            VALIDATOR.validate(sponsor_input),
            Err(MOfNEcdsaValidationError::UnauthorizedSigner)
        );

        Ok(())
    }
}
