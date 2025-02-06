# M-of-N ECDSA Keystore Account Type

This repo implements a keystore account type for use with the Axiom Keystore. Creating a new keystore account type requires implementing a [key data consumer](https://keystore-docs.axiom.xyz/docs/creating-a-keystore-account-type/key-data-consumer) and setting up a [signature prover](https://keystore-docs.axiom.xyz/docs/creating-a-keystore-account-type/signature-prover). We document both below.

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

## Signature Prover
