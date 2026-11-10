//! The text form of the enclave limits: the `NAME=VALUE` pairs of the CLI and
//! of `/etc/utexo/enclave-limits.conf`, and the table that `limits show` prints.
//! The enclave checks the values (`enclave::limits`).

use crate::enclave_proto::Limits;

macro_rules! limit_fields {
    ($($name:ident,)*) => {
        fn field<'a>(limits: &'a mut Limits, name: &str) -> Option<&'a mut u64> {
            match name {
                $(stringify!($name) => Some(&mut limits.$name),)*
                _ => None,
            }
        }

        /// Each limit: its name, and its values in `current` and in `image`.
        pub fn rows(current: &Limits, image: &Limits) -> Vec<(&'static str, u64, u64)> {
            vec![$((stringify!($name), current.$name, image.$name),)*]
        }
    };
}

limit_fields! {
    total_request_timeout_secs,
    io_idle_timeout_secs,
    first_bytes_timeout_secs,
    electrum_timeout_secs,
    esplora_timeout_secs,
    evm_rpc_timeout_secs,
    max_rgb_lib_ms,
    max_witness_check_cost,
    max_bundle_id_cost,
    max_reject_walk_cost,
    max_reject_list_entries,
    reject_list_page_entries,
    max_message_bytes,
    max_wire_elements,
    max_consignment_bytes,
    max_merkle_proofs,
    max_total_proof_bytes,
    max_psbt_bytes,
    max_gas_tx_bytes,
    max_rlp_items,
    max_funds_out_call_data_bytes,
    max_headers_per_submit,
    max_headers_per_minute,
    mint_replay_ttl_secs,
    mint_replay_max_entries,
    mint_max_inputs,
    mint_max_outputs,
}

/// Sets one `NAME=VALUE` pair on `limits`.
fn assign(limits: &mut Limits, pair: &str) -> Result<(), String> {
    let (name, value) = pair
        .split_once('=')
        .ok_or_else(|| format!("{pair:?} is not NAME=VALUE"))?;
    let (name, value) = (name.trim(), value.trim());
    let value: u64 = value
        .parse()
        .map_err(|_| format!("{name}: {value:?} is not a whole number"))?;
    if value == 0 {
        // On the wire, 0 keeps the value. Do not let a 0 here look like a change.
        return Err(format!("{name}: 0 is not a value"));
    }
    let field = field(limits, name)
        .ok_or_else(|| format!("{name:?} is not a limit; `limits show` lists the names"))?;
    *field = value;
    Ok(())
}

/// The limits of `pairs` and of the lines of `file`, if given. A `#` starts a
/// comment. Empty lines are skipped. A pair overrides a line of the file.
pub fn parse(pairs: &[String], file: Option<&str>) -> Result<Limits, String> {
    let mut limits = Limits::default();
    let lines = file
        .into_iter()
        .flat_map(str::lines)
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty());
    for pair in lines.chain(pairs.iter().map(String::as_str)) {
        assign(&mut limits, pair)?;
    }
    Ok(limits)
}

/// The table of `limits show`.
pub fn table(current: &Limits, image: &Limits) -> String {
    let mut out = format!("{:<32} {:>14} {:>14}\n", "limit", "current", "image");
    for (name, current, image) in rows(current, image) {
        let changed = if current == image { "" } else { "  changed" };
        out.push_str(&format!("{name:<32} {current:>14} {image:>14}{changed}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    #[test]
    fn pairs_set_only_the_named_limits() {
        let limits = parse(
            &pairs(&["max_rgb_lib_ms=24000", "total_request_timeout_secs = 40"]),
            None,
        )
        .unwrap();
        assert_eq!(limits.max_rgb_lib_ms, 24_000);
        assert_eq!(limits.total_request_timeout_secs, 40);
        assert_eq!(limits.max_psbt_bytes, 0, "0 keeps the value in the enclave");
    }

    #[test]
    fn a_file_has_comments_and_empty_lines_and_a_pair_overrides_it() {
        let file = "# Longer burns.\n\nmax_rgb_lib_ms=24000  # 24 s\nmax_psbt_bytes=2097152\n";
        let limits = parse(&pairs(&["max_rgb_lib_ms=21000"]), Some(file)).unwrap();
        assert_eq!(limits.max_rgb_lib_ms, 21_000);
        assert_eq!(limits.max_psbt_bytes, 2_097_152);
    }

    #[test]
    fn bad_input_is_refused() {
        for (pair, text) in [
            ("max_rgb_lib_ms", "not NAME=VALUE"),
            ("max_rgb_lib_ms=20s", "not a whole number"),
            ("max_rgb_lib_ms=-1", "not a whole number"),
            ("max_rgb_lib_ms=0", "0 is not a value"),
            ("spv_min_confirmations=1", "not a limit"),
        ] {
            let err = parse(&pairs(&[pair]), None).unwrap_err();
            assert!(err.contains(text), "{pair}: {err}");
        }
    }

    /// Each field of the proto must have a row, so `limits show` and `limits
    /// set` reach every limit. The table groups the limits, so the order can
    /// differ from the proto.
    #[test]
    fn every_limit_has_a_name() {
        let proto = include_str!("../../enclave-proto/proto/enclave.proto");
        let body = proto
            .split("message Limits {")
            .nth(1)
            .and_then(|rest| rest.split('}').next())
            .unwrap();
        let mut names: Vec<&str> = body
            .lines()
            .filter_map(|line| line.trim().strip_prefix("uint64 "))
            .map(|field| field.split(' ').next().unwrap())
            .collect();
        names.sort_unstable();
        let rows = rows(&Limits::default(), &Limits::default());
        let mut rows: Vec<&str> = rows.iter().map(|(name, _, _)| *name).collect();
        rows.sort_unstable();
        assert_eq!(names, rows);
    }
}
