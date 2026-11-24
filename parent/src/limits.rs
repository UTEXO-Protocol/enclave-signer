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
    evm_rpc_timeout_secs,
    max_reject_list_entries,
    reject_list_page_entries,
    max_message_bytes,
    max_wire_elements,
    max_consignment_bytes,
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

/// Names that are reserved in the schema and set nothing. A limits file of an
/// operator can still name one. Such a pair is skipped with a note, so the
/// other limits of the file still apply.
const RESERVED_NAMES: [&str; 4] = [
    "max_rgb_lib_ms",
    "max_witness_check_cost",
    "max_bundle_id_cost",
    "max_reject_walk_cost",
];

/// Sets one `NAME=VALUE` pair on `limits`. Returns a note when the pair was
/// skipped.
fn assign(limits: &mut Limits, pair: &str) -> Result<Option<String>, String> {
    let (name, value) = pair
        .split_once('=')
        .ok_or_else(|| format!("{pair:?} is not NAME=VALUE"))?;
    let (name, value) = (name.trim(), value.trim());
    if RESERVED_NAMES.contains(&name) {
        return Ok(Some(format!(
            "{name} is not a limit of this enclave; the pair is skipped"
        )));
    }
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
    Ok(None)
}

/// The limits of `pairs` and of the lines of `file`, if given. A `#` starts a
/// comment. Empty lines are skipped. A pair overrides a line of the file.
/// Also returns a note for each pair that was skipped.
pub fn parse(pairs: &[String], file: Option<&str>) -> Result<(Limits, Vec<String>), String> {
    let mut limits = Limits::default();
    let mut skipped = Vec::new();
    let lines = file
        .into_iter()
        .flat_map(str::lines)
        .map(|line| line.split('#').next().unwrap_or("").trim())
        .filter(|line| !line.is_empty());
    for pair in lines.chain(pairs.iter().map(String::as_str)) {
        skipped.extend(assign(&mut limits, pair)?);
    }
    Ok((limits, skipped))
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

/// Notes on limits in force above the parent's own `framing::MAX_MESSAGE_SIZE`
/// or `request_shape::MAX_WIRE_ELEMENTS`, which the parent applies first.
pub fn notes(current: &Limits) -> Vec<String> {
    let frame = u64::from(crate::framing::MAX_MESSAGE_SIZE);
    let elements = crate::request_shape::MAX_WIRE_ELEMENTS as u64;
    let mut notes = Vec::new();
    if current.max_message_bytes > frame {
        notes.push(format!(
            "max_message_bytes is {}, but the parent forwards frames of at most {frame} \
             bytes and refuses a larger request first",
            current.max_message_bytes
        ));
    }
    if current.max_wire_elements > elements {
        notes.push(format!(
            "max_wire_elements is {}, but the parent refuses a request of more than \
             {elements} elements first",
            current.max_wire_elements
        ));
    }
    notes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    /// The fixed limits equal the image values; only a higher one gets a note.
    #[test]
    fn a_limit_above_the_fixed_parent_limit_gets_a_note() {
        let image = utexo_bridge_enclave::limits::Limits::DEFAULTS;
        assert_eq!(
            u64::from(crate::framing::MAX_MESSAGE_SIZE),
            image.max_message_bytes
        );
        assert_eq!(
            crate::request_shape::MAX_WIRE_ELEMENTS as u64,
            image.max_wire_elements
        );
        let mut current = Limits {
            max_message_bytes: image.max_message_bytes,
            max_wire_elements: image.max_wire_elements,
            ..Default::default()
        };
        assert!(notes(&current).is_empty());
        current.max_message_bytes += 1;
        current.max_wire_elements += 1;
        let notes = notes(&current);
        assert_eq!(notes.len(), 2, "{notes:?}");
        assert!(notes[0].starts_with("max_message_bytes"), "{notes:?}");
        assert!(notes[1].starts_with("max_wire_elements"), "{notes:?}");
    }

    #[test]
    fn pairs_set_only_the_named_limits() {
        let (limits, _) = parse(
            &pairs(&["evm_rpc_timeout_secs=24", "total_request_timeout_secs = 40"]),
            None,
        )
        .unwrap();
        assert_eq!(limits.evm_rpc_timeout_secs, 24);
        assert_eq!(limits.total_request_timeout_secs, 40);
        assert_eq!(limits.max_psbt_bytes, 0, "0 keeps the value in the enclave");
    }

    #[test]
    fn a_file_has_comments_and_empty_lines_and_a_pair_overrides_it() {
        let file = "# Slower RPC.\n\nevm_rpc_timeout_secs=24  # 24 s\nmax_psbt_bytes=2097152\n";
        let (limits, skipped) = parse(&pairs(&["evm_rpc_timeout_secs=21"]), Some(file)).unwrap();
        assert!(skipped.is_empty());
        assert_eq!(limits.evm_rpc_timeout_secs, 21);
        assert_eq!(limits.max_psbt_bytes, 2_097_152);
    }

    /// A file can still name a limit that is reserved in the schema. The
    /// pair is skipped with a note, and the other limits of the file apply.
    #[test]
    fn a_reserved_name_is_skipped_and_the_rest_of_the_file_applies() {
        let file = "max_rgb_lib_ms=30000\ntotal_request_timeout_secs=320\n";
        let (limits, skipped) = parse(&[], Some(file)).unwrap();
        assert_eq!(limits.total_request_timeout_secs, 320);
        assert_eq!(skipped.len(), 1, "{skipped:?}");
        assert!(skipped[0].starts_with("max_rgb_lib_ms"), "{skipped:?}");
        for name in RESERVED_NAMES {
            let (limits, skipped) = parse(&pairs(&[&format!("{name}=1")]), None).unwrap();
            assert_eq!(limits, Limits::default(), "{name}");
            assert_eq!(skipped.len(), 1, "{name}");
        }
    }

    #[test]
    fn bad_input_is_refused() {
        for (pair, text) in [
            ("evm_rpc_timeout_secs", "not NAME=VALUE"),
            ("evm_rpc_timeout_secs=20s", "not a whole number"),
            ("evm_rpc_timeout_secs=-1", "not a whole number"),
            ("evm_rpc_timeout_secs=0", "0 is not a value"),
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
