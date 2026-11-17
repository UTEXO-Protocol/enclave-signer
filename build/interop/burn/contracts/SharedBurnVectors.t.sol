// SPDX-License-Identifier: MIT
pragma solidity 0.8.35;

import {Test} from "forge-std/Test.sol";
import {Bridge} from "../../src/Bridge.sol";
import {BridgeProxy} from "../../src/BridgeProxy.sol";
import {IBridge} from "../../src/interfaces/IBridge.sol";
import {IMultisigProxy} from "../../src/interfaces/IMultisigProxy.sol";
import {BurnIdHelper} from "../helpers/BurnIdHelper.sol";
import {MultisigHelper} from "../helpers/MultisigHelper.sol";

/// @notice Shared byte mathematics; these checks do not authorize or execute a release.
contract SharedBurnReferenceVectorsTest is Test {
    string private vectors;
    Bridge private bridge;
    bytes32 private domain;

    function setUp() public {
        vectors = vm.envString("BURN_SHARED_VECTORS_JSON");
        assertEq(vm.parseJsonUint(vectors, ".formatVersion"), 1);
        vm.chainId(_number(".domain.chainId"));
        bytes memory init = abi.encodeCall(
            Bridge.initialize,
            (_address(".token"), address(this), payable(address(this)), address(0), 1, 1, address(this))
        );
        deployCodeTo("BridgeProxy.sol:BridgeProxy", abi.encode(address(new Bridge()), init), _address(".bridge"));
        bridge = Bridge(_address(".bridge"));
        assertEq(_text(".domain.name"), "MultisigProxy");
        assertEq(_text(".domain.version"), "1");
        domain = MultisigHelper.domainSeparator(_address(".domain.verifyingContract"), block.chainid);
        assertEq(domain, _word(".domain.separator"));
    }

    function _text(string memory path) private view returns (string memory) {
        return vm.parseJsonString(vectors, path);
    }

    function _number(string memory path) private view returns (uint256) {
        return vm.parseUint(_text(path));
    }

    function _address(string memory path) private view returns (address) {
        return vm.parseJsonAddress(vectors, path);
    }

    function _word(string memory path) private view returns (bytes32) {
        return vm.parseJsonBytes32(vectors, path);
    }

    function _bytes(string memory path) private view returns (bytes memory) {
        return vm.parseJsonBytes(vectors, path);
    }

    function _tail(bytes memory data, uint256 offset) private pure returns (bytes memory result) {
        result = new bytes(data.length - offset);
        for (uint256 i; i < result.length; ++i) {
            result[i] = data[i + offset];
        }
    }

    function test_sharedWitnessCommitmentsAndIdentityReferences() public view {
        bytes32 tag = sha256("urn:lnp-bp:rgb:lock#2026-11-04");
        for (uint256 i; i < 2; ++i) {
            string memory path = string.concat(".mints[", vm.toString(i), "]");
            bytes32 lockId = sha256(
                abi.encodePacked(
                    tag, tag, _word(string.concat(path, ".opId")), _word(string.concat(path, ".witnessTxidInternal"))
                )
            );
            assertEq(lockId, _word(string.concat(path, ".lockId")));
            assertEq(
                bridge.rgbMintDepositId(
                    _number(".rgbNetwork"), uint256(lockId), _number(string.concat(path, ".amount"))
                ),
                _word(string.concat(path, ".depositId"))
            );
        }
        assertEq(
            BurnIdHelper.derive(
                address(bridge),
                block.chainid,
                _address(".token"),
                _number(".burn.amount"),
                _number(".rgbNetwork"),
                _text(".burn.sourceAddress"),
                _word(".burn.sourceBurnTxId")
            ),
            uint256(_word(".burn.id"))
        );
    }

    function _assertDigest(string memory path, bytes32 digest) private view {
        bytes32 expected = _word(string.concat(path, ".expected.digest"));
        assertEq(digest, expected);
        assertEq(MultisigHelper.toTypedDataHash(domain, _word(string.concat(path, ".expected.structHash"))), expected);
    }

    function test_sharedDirectCalldataAndDigestReference() public view {
        string memory path = ".releases[0]";
        bytes memory data = _bytes(string.concat(path, ".expected.calldata"));
        IBridge.FundsOutParams memory params = abi.decode(_tail(data, 4), (IBridge.FundsOutParams));
        assertEq(data, abi.encodeCall(IBridge.fundsOut, (params)));
        assertEq(MultisigHelper.TEE_FUNDS_OUT_TYPEHASH, _word(string.concat(path, ".expected.typeHash")));
        _assertDigest(
            path,
            MultisigHelper.digestTeeFundsOut(
                domain, params, _number(string.concat(path, ".nonce")), _number(string.concat(path, ".deadline"))
            )
        );
    }

    function test_sharedLayerzeroCalldataAndDigestReference() public view {
        string memory path = ".releases[1]";
        bytes memory data = _bytes(string.concat(path, ".expected.calldata"));
        // The signing intent has flat parameters; a dynamic Solidity struct adds one outer offset.
        IMultisigProxy.LzFundsOutParams memory params =
            abi.decode(bytes.concat(bytes32(uint256(32)), _tail(data, 4)), (IMultisigProxy.LzFundsOutParams));
        bytes4 selector = bytes4(
            keccak256(
                "lzFundsOut(uint256,uint256,uint256,uint256,string,bytes,bytes,uint32,bytes32,uint256,bytes,bytes32)"
            )
        );
        assertEq(data, bytes.concat(selector, _tail(abi.encode(params), 32)));
        assertEq(MultisigHelper.TEE_LZ_FUNDS_OUT_TYPEHASH, _word(string.concat(path, ".expected.typeHash")));
        _assertDigest(
            path,
            MultisigHelper.digestTeeLzFundsOut(
                domain, params, _number(string.concat(path, ".nonce")), _number(string.concat(path, ".deadline"))
            )
        );
    }
}
