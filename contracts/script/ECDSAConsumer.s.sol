// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import { ECDSAConsumer } from "../src/ECDSAConsumer.sol";

import { Script, safeconsole as console, console2 } from "forge-std/Script.sol";

import { stdJson as StdJson } from "forge-std/StdJson.sol";

using StdJson for string;

interface IKeystoreValidator {
    function deployAndRegisterKeyDataConsumer(bytes memory bytecode) external;
}

contract ECDSAConsumerScript is Script {
    /// @dev Included to enable compilation of the script without a $MNEMONIC environment variable.
    string internal constant TEST_MNEMONIC = "test test test test test test test test test test test junk";

    address internal broadcaster;

    string internal mnemonic;

    string configPath = "./deployment-config/ECDSAConsumer.json";

    modifier broadcast() {
        vm.startBroadcast(broadcaster);
        _;
        vm.stopBroadcast();
    }

    constructor() {
        address from = vm.envOr({ name: "ETH_FROM", defaultValue: address(0) });
        if (from != address(0)) {
            broadcaster = from;
        } else {
            mnemonic = vm.envOr({ name: "MNEMONIC", defaultValue: TEST_MNEMONIC });
            (broadcaster,) = deriveRememberKey({ mnemonic: mnemonic, index: 0 });
        }
    }

    function run() external broadcast {
        string memory config = vm.readFile(configPath);

        IKeystoreValidator validator = IKeystoreValidator(config.readAddress(".keystoreValidator"));
        validator.deployAndRegisterKeyDataConsumer(type(ECDSAConsumer).creationCode);

        console.log("Consumer creation codehash");
        console2.logBytes32(keccak256(type(ECDSAConsumer).creationCode));
    }
}
