// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {BaseAuthorizationModule} from "./BaseAuthorizationModule.sol";
import {UserOperation} from "@account-abstraction/contracts/interfaces/UserOperation.sol";
import {Base64} from "@openzeppelin/contracts/utils/Base64.sol";
import {Secp256r1} from "./PasskeyValidationModules/Secp256r1.sol";
import {IAuthorizationModule} from "../interfaces/IAuthorizationModule.sol";

/**
 * @title Passkey ownership Authorization module for Biconomy Smart Accounts.
 * @dev Compatible with Biconomy Modular Interface v 0.2
 *         - It allows to validate user operations signed by passkeys.
 *         - One owner per Smart Account.
 *         For Smart Contract Owners check SmartContractOwnership module instead
 * @author Aman Raj - <aman.raj@biconomy.io>
 */
contract PasskeyRegistryModule is
    BaseAuthorizationModule
{
    string public constant NAME = "PassKeys Ownership verification Module";
    string public constant VERSION = "1.0.0";

    /// @inheritdoc IAuthorizationModule
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256[2] memory q
    ) external view virtual returns (uint256) {
        if (_verifySignature(userOpHash, userOp.signature, q)) {
            return VALIDATION_SUCCESS;
        }
        return SIG_VALIDATION_FAILED;
    }

    function parseSignature(bytes memory moduleSignature, bytes32 userOpDataHash)external pure returns(uint256 sigx, uint256 sigy, bytes memory authenticatorData, string memory clientDataJSONPre, string memory clientDataJSONPost, string memory opHashBase64, string memory clientDataJSON){
        (   sigx,
            sigy,
            authenticatorData,
            clientDataJSONPre,
            clientDataJSONPost
        ) = abi.decode(
                moduleSignature,
                (uint256, uint256, bytes, string, string)
            );
        
        string memory opHashBase64Str = Base64.encode(
            bytes.concat(userOpDataHash)
        );
        bytes memory strBytes = bytes(opHashBase64Str);
        bytes memory tempResult = new bytes(strBytes.length);
            uint256 resultLength = 0;

            for (uint256 i = 0; i < strBytes.length; i++) {
                if (strBytes[i] == "+") {
                    tempResult[resultLength] = "-";
                } else if (strBytes[i] == "/") {
                    tempResult[resultLength] = "_";
                } else if (strBytes[i] == "=") {
                    continue; // Skip `=`, effectively removing it
                } else {
                    tempResult[resultLength] = strBytes[i];
                }
                resultLength++;
            }

            // Create the final result with the exact length
            bytes memory finalResult = new bytes(resultLength);
            for (uint256 j = 0; j < resultLength; j++) {
                finalResult[j] = tempResult[j];
            }

        opHashBase64 = string(finalResult);

        clientDataJSON = string.concat(
            clientDataJSONPre,
            opHashBase64,
            clientDataJSONPost
        );
    }

    /**
     * @dev Internal utility function to verify a signature.
     * @param userOpDataHash The hash of the user operation data.
     * @param moduleSignature The signature provided by the module.
     * @param q The smart account address.
     * @return True if the signature is valid, false otherwise.
     */
    function _verifySignature(
        bytes32 userOpDataHash,
        bytes memory moduleSignature,
        uint256[2] memory q
    ) internal view returns (bool) {
        (
            uint256 sigx,
            uint256 sigy,
            bytes memory authenticatorData,
            string memory clientDataJSONPre,
            string memory clientDataJSONPost
        ) = abi.decode(
                moduleSignature,
                (uint256, uint256, bytes, string, string)
            );

        string memory opHashBase64 = Base64.encode(
            bytes.concat(userOpDataHash)
        );

        bytes memory strBytes = bytes(opHashBase64);
        bytes memory tempResult = new bytes(strBytes.length);
            uint256 resultLength = 0;

            for (uint256 i = 0; i < strBytes.length; i++) {
                if (strBytes[i] == "+") {
                    tempResult[resultLength] = "-";
                } else if (strBytes[i] == "/") {
                    tempResult[resultLength] = "_";
                } else if (strBytes[i] == "=") {
                    continue; // Skip `=`, effectively removing it
                } else {
                    tempResult[resultLength] = strBytes[i];
                }
                resultLength++;
            }

            // Create the final result with the exact length
            bytes memory finalResult = new bytes(resultLength);
            for (uint256 j = 0; j < resultLength; j++) {
                finalResult[j] = tempResult[j];
            }

        opHashBase64 = string(finalResult);
        string memory clientDataJSON = string.concat(
            clientDataJSONPre,
            opHashBase64,
            clientDataJSONPost
        );
        bytes32 clientHash = sha256(bytes(clientDataJSON));
        bytes32 sigHash = sha256(bytes.concat(authenticatorData, clientHash));

        return Secp256r1.Verify(q, sigx, sigy, uint256(sigHash));
    }
}
