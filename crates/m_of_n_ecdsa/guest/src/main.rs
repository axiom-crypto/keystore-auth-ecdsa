use m_of_n_ecdsa_guest::{verify, MOfNEcdsaInput};
use openvm::io::read;
#[allow(unused_imports)]
use openvm_ecc_guest::k256::Secp256k1Point;
use signature_prover_guest::{set_public_values, KeyData};

// Macro to initialize the moduli for the secp256k1 curve, with the first value being the prime modulus
// and the second being the order of the curve
openvm_algebra_moduli_macros::moduli_init! {
    "0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F",
    "0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141"
}

// Macro to initialize the secp256k1 point type
openvm_ecc_sw_macros::sw_init! {
    Secp256k1Point,
}

pub fn main() {
    // Functions to setup moduli and curve parameters
    setup_all_moduli();
    setup_all_curves();

    // Read the program inputs as a `MOfNEcdsaInput` struct
    let inputs: MOfNEcdsaInput = read();

    // Set data_hash and msg_hash as user public values
    let data_hash = inputs.key_data.data_hash();
    set_public_values(data_hash, inputs.msg_hash);

    // Run ECDSA signature verification on the inputs
    verify(inputs);
}
