use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::PublicKey;

/// Determine whether we should sign a specific PSBT input.
/// Checks (in order):
/// 1. If our pubkey already has a partial_sig — skip (already signed)
/// 2. If our pubkey is in bip32_derivation — sign
/// 3. If the witness_script contains our compressed pubkey bytes — sign
/// 4. Otherwise — skip
pub fn should_sign_segwit_input(psbt: &Psbt, input_index: usize, our_pubkey: &PublicKey) -> bool {
    let input = &psbt.inputs[input_index];
    let our_bitcoin_pubkey = bitcoin::PublicKey::new(*our_pubkey);

    // Already signed? Skip.
    if input.partial_sigs.contains_key(&our_bitcoin_pubkey) {
        return false;
    }

    // In BIP-32 derivation map? Sign.
    // Note: bip32_derivation uses secp256k1::PublicKey as key type
    if input.bip32_derivation.contains_key(our_pubkey) {
        return true;
    }

    // In witness script? Sign (sliding window over script bytes for 33-byte compressed pubkey).
    if let Some(script) = &input.witness_script {
        let script_bytes = script.as_bytes();
        let pubkey_bytes = our_pubkey.serialize(); // 33-byte compressed
        if script_bytes.windows(33).any(|w| w == pubkey_bytes) {
            return true;
        }
    }

    false
}
