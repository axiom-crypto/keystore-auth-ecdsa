# M-of-N ECDSA Keystore Account Type

This repo implements a keystore account type based on M-of-N ECDSA signatures for use with the Axiom Keystore. Creating a new keystore account type requires:

1. Implementing a [Key Data Consumer](https://keystore-docs.axiom.xyz/docs/creating-a-keystore-account-type/key-data-consumer).
2. Implementing a [ZK Authentication Rule](https://keystore-docs.axiom.xyz/docs/creating-a-keystore-account-type/overview).
3. Setting up a [Signature Prover](https://keystore-docs.axiom.xyz/docs/creating-a-keystore-account-type/signature-prover).

## Key Data Consumer

We implement the `IKeyDataConsumer` interface

```solidity
function consumeKeyData(bytes calldata keyData, bytes calldata authData, bytes32 userOpHash) external;
```

where 

- `keyData` is expected to be of the form `abi.encodePacked(bytes1(0x00), abi.encode(ecdsaConsumerCodehash, requiredSigners, allowedSignersList))`.
    - `0x00` is a domain separator.
    - `bytes32 ecdsaConsumerCodehash` is the creation codehash of the `ECDSAConsumer` contract.
    - `uint256 requiredSigners` is the number of signers required to sign the user operation for execution.
    - `address[] allowedSignersList` is the list of allowed signers.
- `authData` is expected to be a concatenated list of signatures where a signature `(uint256 r, uint256 s, uint8 v)` is encoded as the 65-byte payload `abi.encodePacked(r, s, v)`.
- `userOpHash` is a commitment to the user operation that is being executed and the value that signers should be signing.

The implementation also makes the following assumptions:
- There are no duplicate addresses in the `allowedSignersList`.
- The maximum length of `allowedSignersList` is 256.

The contract verifies that the list of signatures recover to at least `requiredSigners` unique addresses in the `allowedSignersList` array. Otherwise, it reverts.

## ZK Authentication Rule

In the `m_of_n_ecdsa/guest` crate we define the our M-of-N ECDSA ZK authentication rule.

First, we define the authentication input, `MOfNEcdsaInput`, as follows:

```rust
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
        .. snip ..
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MOfNEcdsaAuthData {
    pub signatures: Vec<FixedBytes<65>>,
}
```

We have used the `SignatureProverInput` struct and `KeyData` traits defined in the [Keystore Periphery](https://github.com/axiom-crypto/keystore-periphery).

Next we define the authentication rule for a given `MOfNEcdsaInput`.

```rust
/// Circuit statement:
/// * keccak256(abi.encodePacked(0x00, abi.encode(codehash, m, eoa_addrs))) == data_hash
/// * there are [ECDSA signatures] for msg_hash which verifies against [pub_keys]
/// * [eoa_addrs] corresponds to [pub_keys]
pub fn verify(inputs: MOfNEcdsaInput) {
    .. snip ..
}
```

## Signature Prover

`m_of_n_ecdsa_server` wraps the guest program to serve it as a signature prover server, built on the libraries defined in the [Keystore Periphery](https://github.com/axiom-crypto/keystore-periphery).

Signature prover server implements:

- **Input Decoder (`MOfNEcdsaInputDecoder`)**: decodes raw JSON-RPC inputs (`AuthInputs` type) into the `MOfNEcdsaInput` type.
- **Input Validator (`MOfNEcdsaValidator`)**: validates a given `MOfNEcdsaInput`. The validation logic should exactly match the logic in the OpenVM guest program, since it is the last step before the inputs are passed to the guest program to be proven. Because proof generation takes a long time and is computationally expensive, all input errors should ideally be caught by validation before proof generation.
- **Signature prover server binary**: serves the guest program as a signature prover server.

Additionally, the signature prover server implements:
- Test suite: to run and test the guest program.
- Keygen: to generate the proving and verifying keys.
