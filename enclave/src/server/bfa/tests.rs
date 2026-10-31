use super::*;
use crate::config::BridgeConfig;
use crate::error::Result;
use crate::networks::evm::events::{
    rgb_mint_deposit_id, BlockData, EvmReceiptProvider, ReceiptData,
};
use crate::state::EnclaveState;
use crate::test_support::regtest_header_chain;
use attestation_verify::EvmFinalityTag;

const BRIDGE: [u8; 20] = [0x50; 20];
const CHAIN_ID: u64 = 42161;

fn config() -> BridgeConfig {
    BridgeConfig {
        funds_in_contract: BRIDGE,
        token_contract: [0x7e; 20],
        chain_id: CHAIN_ID,
        ..BridgeConfig::default()
    }
}

fn context(cfg: BridgeConfig, rpc: Box<dyn EvmReceiptProvider + Send + Sync>) -> ServerContext {
    let mut ctx = ServerContext::new(EnclaveState::default(), cfg, regtest_header_chain());
    ctx.launch.get_mut().unwrap().evm_rpc_client = Some(rpc);
    ctx
}

/// A binder that must not read the chain.
struct NoRpc;

impl EvmReceiptProvider for NoRpc {
    fn get_transaction_receipt(&self, _: &[u8; 32]) -> Result<Option<ReceiptData>> {
        panic!("this binder must not read the chain")
    }

    fn get_block_by_tag(&self, _: EvmFinalityTag) -> Result<Option<BlockData>> {
        panic!("this binder must not read the chain")
    }

    fn get_block_by_number(&self, _: u64) -> Result<Option<BlockData>> {
        panic!("this binder must not read the chain")
    }

    fn get_chain_id(&self) -> Result<u64> {
        panic!("this binder must not read the chain")
    }
}

#[cfg(rgb_to_evm)]
mod burn {
    use super::*;
    use crate::networks::rgb::validation::{BfaBridge, MintAnchor};

    const PINNED: BfaBridge = BfaBridge {
        chain_id: CHAIN_ID,
        address: BRIDGE,
    };

    fn anchor(tag: u8, amount: u64, in_last_bundle: bool) -> MintAnchor {
        MintAnchor {
            opid: [tag; 32],
            amount,
            before_block: 110,
            in_last_bundle,
        }
    }

    /// Finding 47: a burn's locks come from its mints alone.
    #[test]
    fn derives_every_lock_from_its_anchor_without_rpc() {
        let ctx = context(config(), Box::new(NoRpc));
        let anchors = [anchor(1, 100_000, false), anchor(2, 5, true)];

        let bound = derived_locks(&ctx, &PINNED, &anchors).unwrap();
        assert_eq!(bound.evm_chain_id, CHAIN_ID);
        assert_eq!(bound.locks.len(), 2);
        for (lock, a) in bound.locks.iter().zip(&anchors) {
            assert_eq!(lock.mint_opid, a.opid);
            assert_eq!(lock.minted, a.amount);
            assert_eq!(lock.net_amount, a.amount);
            assert_eq!(
                lock.operation_id,
                rgb_mint_deposit_id(&ctx.bridge_config, &a.opid, a.amount).unwrap()
            );
        }
    }

    #[test]
    fn refuses_when_the_token_is_not_pinned() {
        let cfg = BridgeConfig {
            token_contract: [0; 20],
            ..config()
        };
        let ctx = context(cfg, Box::new(NoRpc));
        let err = derived_locks(&ctx, &PINNED, &[anchor(1, 1, false)]).unwrap_err();
        assert!(err.to_string().contains("TOKEN_CONTRACT"), "{err}");
    }

    #[test]
    fn refuses_an_asset_of_another_bridge_or_chain() {
        let ctx = context(config(), Box::new(NoRpc));
        for bridge in [
            BfaBridge {
                address: [0x51; 20],
                ..PINNED
            },
            BfaBridge {
                chain_id: 1,
                ..PINNED
            },
        ] {
            let err = derived_locks(&ctx, &bridge, &[anchor(1, 1, false)]).unwrap_err();
            assert!(err.to_string().contains("is not the pinned"), "{err}");
        }
    }
}

#[cfg(evm_to_rgb)]
mod mint {
    use super::*;
    use crate::networks::evm::events::{LogEntry, BRIDGE_FUNDS_IN_SIG, FUNDS_IN_SIG};
    use crate::networks::rgb::psbt_validation::{MintFacts, MintRecipient};
    use crate::test_support::{abi_word, bridge_funds_in_data, FakeEvm};
    use sha3::{Digest, Keccak256};

    const TX: [u8; 32] = [0xee; 32];

    fn topic0(sig: &str) -> [u8; 32] {
        Keccak256::digest(sig.as_bytes()).into()
    }

    /// A deposit for mint `opid` of `amount`, with `operation_id`, at block 100.
    fn deposit(opid: [u8; 32], amount: u64, operation_id: [u8; 32]) -> FakeEvm {
        let logs = vec![
            LogEntry {
                address: BRIDGE,
                topics: vec![topic0(FUNDS_IN_SIG), abi_word(0xdead), opid],
                data: abi_word(amount).to_vec(),
            },
            LogEntry {
                address: BRIDGE,
                topics: vec![topic0(BRIDGE_FUNDS_IN_SIG), operation_id],
                data: bridge_funds_in_data(amount, amount, 0, ""),
            },
        ];
        FakeEvm {
            receipt: Some(ReceiptData {
                status_success: true,
                block_number: 100,
                block_hash: [0x42; 32],
                logs,
            }),
            chain_id: CHAIN_ID,
        }
    }

    fn paid(opid: [u8; 32], amount: u64) -> FakeEvm {
        let id = rgb_mint_deposit_id(&config(), &opid, amount).unwrap();
        deposit(opid, amount, id)
    }

    /// The mint a PSBT commits: `issued` units of mint `[2; 32]`, before block 110.
    fn mint(issued: u64) -> MintFacts {
        MintFacts {
            right: rgbstd::Opout::new(rgbstd::OpId::from([1; 32]), schemata::OS_MINT, 0),
            opid: [2; 32],
            issued,
            before_block: 110,
            recipient: MintRecipient::Blinded("utxob:recipient".into()),
        }
    }

    fn bind(ctx: &ServerContext, mint: &MintFacts) -> String {
        bind_mint_deposit(ctx, &TX, mint).unwrap_err().to_string()
    }

    #[test]
    fn binds_the_mint_to_its_receipt() {
        let ctx = context(config(), Box::new(paid([2; 32], 100)));
        bind_mint_deposit(&ctx, &TX, &mint(100)).unwrap();
    }

    #[test]
    fn refuses_a_shadow_deposit_for_the_same_mint() {
        let ctx = context(config(), Box::new(deposit([2; 32], 100, [0xd2; 32])));
        let err = bind(&ctx, &mint(100));
        assert!(err.contains("not the one mint"), "{err}");
    }

    #[test]
    fn refuses_deposit_of_other_amount() {
        let ctx = context(config(), Box::new(paid([2; 32], 99)));
        let err = bind(&ctx, &mint(100));
        assert!(err.contains("not the one mint"), "{err}");
    }

    #[test]
    fn refuses_deposit_of_other_opid() {
        let ctx = context(config(), Box::new(paid([3; 32], 100)));
        let err = bind(&ctx, &mint(100));
        assert!(err.contains("rgbOpId mismatch"), "{err}");
    }

    /// An RGB receiver refuses a lock at or after the mint's `beforeBlock`.
    #[test]
    fn refuses_deposit_at_or_after_before_block() {
        let ctx = context(config(), Box::new(paid([2; 32], 100)));
        for before_block in [100, 99] {
            let late = MintFacts {
                before_block,
                ..mint(100)
            };
            let err = bind(&ctx, &late);
            assert!(err.contains("not before the mint's beforeBlock"), "{err}");
        }
    }

    #[test]
    fn refuses_a_node_on_another_chain() {
        let node = FakeEvm {
            chain_id: 1,
            ..paid([2; 32], 100)
        };
        let ctx = context(config(), Box::new(node));
        let err = bind(&ctx, &mint(100));
        assert!(err.contains("reports chain id 1"), "{err}");
    }

    /// A node whose `covered` head holds the lock and whose other heads are
    /// below it.
    struct TaggedHeads {
        node: FakeEvm,
        covered: EvmFinalityTag,
    }

    impl EvmReceiptProvider for TaggedHeads {
        fn get_transaction_receipt(&self, tx: &[u8; 32]) -> Result<Option<ReceiptData>> {
            self.node.get_transaction_receipt(tx)
        }

        fn get_block_by_tag(&self, tag: EvmFinalityTag) -> Result<Option<BlockData>> {
            if tag == self.covered {
                return self.node.get_block_by_tag(tag);
            }
            self.node.get_block_by_number(99)
        }

        fn get_block_by_number(&self, number: u64) -> Result<Option<BlockData>> {
            self.node.get_block_by_number(number)
        }

        fn get_chain_id(&self) -> Result<u64> {
            self.node.get_chain_id()
        }
    }

    /// The mint lock follows the attested `EVM_FINALITY_TAG`, not a fixed tag.
    #[test]
    fn checks_the_lock_against_the_configured_finality_tag() {
        for tag in [
            EvmFinalityTag::Latest,
            EvmFinalityTag::Safe,
            EvmFinalityTag::Finalized,
        ] {
            let cfg = BridgeConfig {
                evm_finality_tag: tag,
                ..config()
            };
            let covered = TaggedHeads {
                node: paid([2; 32], 100),
                covered: tag,
            };
            let ctx = context(cfg.clone(), Box::new(covered));
            assert!(bind_mint_deposit(&ctx, &TX, &mint(100)).is_ok(), "{tag}");

            let other = if tag == EvmFinalityTag::Safe {
                EvmFinalityTag::Finalized
            } else {
                EvmFinalityTag::Safe
            };
            let below = TaggedHeads {
                node: paid([2; 32], 100),
                covered: other,
            };
            let ctx = context(cfg, Box::new(below));
            let err = bind(&ctx, &mint(100));
            assert!(err.contains(&format!("above RPC {tag} block 99")), "{err}");
        }
    }

    /// The pins are checked before any RPC read.
    #[test]
    fn refuses_an_unpinned_token_before_reading_the_chain() {
        let cfg = BridgeConfig {
            token_contract: [0; 20],
            ..config()
        };
        let ctx = context(cfg, Box::new(NoRpc));
        let err = bind(&ctx, &mint(100));
        assert!(err.contains("TOKEN_CONTRACT"), "{err}");
    }

    const DERIVED: VerifiedLock = VerifiedLock {
        mint_opid: [1; 32],
        minted: 100,
        operation_id: [0xd1; 32],
        net_amount: 100,
    };

    #[test]
    fn accepts_the_deposit_the_mint_derives() {
        assert!(bind_request_deposit(&DERIVED, &DERIVED).is_ok());
    }

    #[test]
    fn refuses_another_net_amount_for_the_same_deposit() {
        let other = VerifiedLock {
            net_amount: 99,
            ..DERIVED
        };
        assert!(bind_request_deposit(&DERIVED, &other).is_err());
    }
}
