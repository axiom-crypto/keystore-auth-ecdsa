// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { MessageHashUtils } from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import { Test, console } from "forge-std/Test.sol";

import { ECDSAConsumer } from "../src/ECDSAConsumer.sol";

using MessageHashUtils for bytes32;

contract ECDSAConsumerTest is Test {
    ECDSAConsumer public consumer;
    address[] public allowedSignersList;
    uint256 privKey1;

    function setUp() public {
        consumer = new ECDSAConsumer();

        (address address1, uint256 _privKey1) = makeAddrAndKey("address1");
        (address address2,) = makeAddrAndKey("address2");

        privKey1 = _privKey1;

        allowedSignersList.push(address1);
        allowedSignersList.push(address2);
    }

    function test_simple() public view {
        // codehash doesn't matter here
        bytes memory keyData =
            _constructKeyData({ codehash: bytes32(0), requiredSigners: 1, _allowedSignersList: allowedSignersList });

        bytes32 msgHash = keccak256("msgHash");

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privKey1, msgHash.toEthSignedMessageHash());

        bytes memory signature = abi.encodePacked(r, s, v);

        consumer.consumeKeyData({ keyData: keyData, walletSignatures: signature, userOpHash: msgHash });
    }

    function _constructKeyData(bytes32 codehash, uint256 requiredSigners, address[] memory _allowedSignersList)
        internal
        pure
        returns (bytes memory)
    {
        require(
            requiredSigners <= _allowedSignersList.length,
            "Required signers must be less than or equal to allowed signers list length"
        );

        return abi.encodePacked(bytes1(0x00), abi.encode(codehash, requiredSigners, _allowedSignersList));
    }
}
