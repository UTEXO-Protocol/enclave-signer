//! BER -> DER normalisation for the KMS recipient envelope.
//!
//! AWS KMS emits `CiphertextForRecipient` as streaming BER (X.690 §8.1.3.6):
//! constructed values carry the indefinite length `0x80 ... 00 00`, and the
//! encrypted content arrives as a constructed OCTET STRING made of primitive
//! chunks. The RustCrypto `der` parser accepts only DER, so the envelope is
//! transcoded first: every length becomes definite and minimal, and chunked
//! strings are joined into one primitive. Nothing else is reinterpreted; the
//! typed CMS decode in `recipient.rs` still validates the structure.
//!
//! The transcoder is total on its bounded input: it never panics, refuses
//! anything it cannot account for byte by byte, and caps nesting depth.

/// Deepest nesting accepted. A CMS EnvelopedData is six levels deep.
const MAX_DEPTH: usize = 16;
/// Longest tag (identifier octets) accepted: one leading byte plus three
/// continuation bytes, far beyond any CMS tag.
const MAX_TAG_BYTES: usize = 4;
/// Longest definite length field accepted (4 octets = u32), which already
/// exceeds the envelope cap.
const MAX_LENGTH_BYTES: usize = 4;

const UNIVERSAL_OCTET_STRING: u8 = 0x04;
const CONSTRUCTED: u8 = 0x20;
const CLASS_MASK: u8 = 0xC0;
const CLASS_CONTEXT: u8 = 0x80;

struct Node {
    tag: Vec<u8>,
    body: Body,
}

enum Body {
    Primitive(Vec<u8>),
    Constructed(Vec<Node>),
}

/// Transcode `input` (BER or DER) to DER. `None` when the input is not a
/// single, complete, well-formed BER value.
pub(super) fn ber_to_der(input: &[u8]) -> Option<Vec<u8>> {
    let (node, used) = parse(input, 0)?;
    if used != input.len() {
        return None;
    }
    let mut out = Vec::with_capacity(input.len());
    node.encode(&mut out);
    Some(out)
}

/// Parse one TLV at the start of `input`. Returns the node and bytes consumed.
fn parse(input: &[u8], depth: usize) -> Option<(Node, usize)> {
    if depth > MAX_DEPTH || input.len() < 2 {
        return None;
    }
    // Identifier octets.
    let first = input[0];
    let mut offset = 1;
    if first & 0x1F == 0x1F {
        loop {
            let b = *input.get(offset)?;
            offset += 1;
            if offset > MAX_TAG_BYTES {
                return None;
            }
            if b & 0x80 == 0 {
                break;
            }
        }
    }
    let tag = input[..offset].to_vec();
    let constructed = first & CONSTRUCTED != 0;

    // Length octets.
    let l = *input.get(offset)?;
    offset += 1;
    let length = if l < 0x80 {
        Some(usize::from(l))
    } else if l == 0x80 {
        None
    } else {
        let n = usize::from(l & 0x7F);
        if n > MAX_LENGTH_BYTES {
            return None;
        }
        let bytes = input.get(offset..offset + n)?;
        if bytes[0] == 0 {
            return None;
        }
        offset += n;
        let mut v = 0usize;
        for b in bytes {
            v = (v << 8) | usize::from(*b);
        }
        Some(v)
    };

    let body = match (length, constructed) {
        (Some(len), false) => {
            let content = input.get(offset..offset + len)?;
            offset += len;
            Body::Primitive(content.to_vec())
        }
        (Some(len), true) => {
            let end = offset.checked_add(len)?;
            if end > input.len() {
                return None;
            }
            let mut children = Vec::new();
            while offset < end {
                let (child, used) = parse(&input[offset..end], depth + 1)?;
                offset += used;
                children.push(child);
            }
            Body::Constructed(children)
        }
        (None, false) => return None,
        (None, true) => {
            let mut children = Vec::new();
            loop {
                let rest = input.get(offset..)?;
                if rest.len() >= 2 && rest[0] == 0 && rest[1] == 0 {
                    offset += 2;
                    break;
                }
                let (child, used) = parse(rest, depth + 1)?;
                offset += used;
                children.push(child);
            }
            Body::Constructed(children)
        }
    };

    Some((Node { tag, body }.joined(), offset))
}

impl Node {
    /// Join a constructed string back into one primitive. Applies to a
    /// constructed universal OCTET STRING and to a constructed context-specific
    /// value whose parts are all primitive OCTET STRINGs (the IMPLICIT
    /// `encryptedContent [0]` in `EncryptedContentInfo`).
    fn joined(self) -> Node {
        let Body::Constructed(children) = &self.body else {
            return self;
        };
        let first = self.tag[0];
        let eligible = self.tag.len() == 1
            && (first == UNIVERSAL_OCTET_STRING | CONSTRUCTED
                || first & CLASS_MASK == CLASS_CONTEXT);
        let all_chunks = !children.is_empty()
            && children.iter().all(|c| {
                c.tag.as_slice() == [UNIVERSAL_OCTET_STRING] && matches!(c.body, Body::Primitive(_))
            });
        if !(eligible && all_chunks) {
            return self;
        }
        let mut joined = Vec::new();
        for child in children {
            if let Body::Primitive(bytes) = &child.body {
                joined.extend_from_slice(bytes);
            }
        }
        Node {
            tag: vec![first & !CONSTRUCTED],
            body: Body::Primitive(joined),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.tag);
        match &self.body {
            Body::Primitive(bytes) => {
                encode_length(bytes.len(), out);
                out.extend_from_slice(bytes);
            }
            Body::Constructed(children) => {
                let mut inner = Vec::new();
                for child in children {
                    child.encode(&mut inner);
                }
                encode_length(inner.len(), out);
                out.extend_from_slice(&inner);
            }
        }
    }
}

fn encode_length(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let skip = bytes.iter().take_while(|b| **b == 0).count();
    out.push(0x80 | (bytes.len() - skip) as u8);
    out.extend_from_slice(&bytes[skip..]);
}

#[cfg(test)]
pub(super) mod test_support {
    //! Turns DER into the streaming BER shape KMS produces, for tests.

    /// Re-encode `der` with indefinite lengths on every constructed value and
    /// every OCTET STRING (universal or context `[0]`) longer than one byte
    /// split into two constructed chunks.
    pub(crate) fn to_streaming_ber(der: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let used = walk(der, &mut out);
        assert_eq!(
            used,
            der.len(),
            "test helper expects one complete DER value"
        );
        out
    }

    fn walk(input: &[u8], out: &mut Vec<u8>) -> usize {
        let first = input[0];
        let mut offset = 1;
        if first & 0x1F == 0x1F {
            while input[offset] & 0x80 != 0 {
                offset += 1;
            }
            offset += 1;
        }
        let tag = &input[..offset];
        let l = input[offset];
        offset += 1;
        let len = if l < 0x80 {
            usize::from(l)
        } else {
            let n = usize::from(l & 0x7F);
            let mut v = 0usize;
            for b in &input[offset..offset + n] {
                v = (v << 8) | usize::from(*b);
            }
            offset += n;
            v
        };
        let content = &input[offset..offset + len];
        if first & 0x20 != 0 {
            out.extend_from_slice(tag);
            out.push(0x80);
            let mut inner = 0;
            while inner < content.len() {
                inner += walk(&content[inner..], out);
            }
            out.extend_from_slice(&[0, 0]);
        } else if tag.len() == 1 && (first == 0x04 || first == 0x80) && content.len() > 1 {
            out.push(first | 0x20);
            out.push(0x80);
            let (a, b) = content.split_at(content.len() / 2);
            for chunk in [a, b] {
                out.push(0x04);
                super::encode_length(chunk.len(), out);
                out.extend_from_slice(chunk);
            }
            out.extend_from_slice(&[0, 0]);
        } else {
            out.extend_from_slice(tag);
            super::encode_length(len, out);
            out.extend_from_slice(content);
        }
        offset + len
    }
}

#[cfg(test)]
mod tests {
    use super::{ber_to_der, test_support::to_streaming_ber};

    #[test]
    fn der_passes_through_unchanged() {
        let der = [0x30, 0x06, 0x04, 0x01, 0xAA, 0x04, 0x01, 0xBB];
        assert_eq!(ber_to_der(&der).unwrap(), der);
        let long: Vec<u8> = [vec![0x04, 0x81, 0x80], vec![1u8; 128]].concat();
        assert_eq!(ber_to_der(&long).unwrap(), long);
    }

    #[test]
    fn indefinite_lengths_become_definite() {
        let ber = [0x30, 0x80, 0x04, 0x01, 0xAA, 0x04, 0x01, 0xBB, 0x00, 0x00];
        assert_eq!(
            ber_to_der(&ber).unwrap(),
            [0x30, 0x06, 0x04, 0x01, 0xAA, 0x04, 0x01, 0xBB]
        );
        // Nested indefinite inside definite, and non-minimal long form.
        let ber = [0x30, 0x81, 0x07, 0x30, 0x80, 0x04, 0x01, 0xAA, 0x00, 0x00];
        assert_eq!(
            ber_to_der(&ber).unwrap(),
            [0x30, 0x05, 0x30, 0x03, 0x04, 0x01, 0xAA]
        );
    }

    #[test]
    fn constructed_strings_are_joined() {
        let ber = [0x24, 0x80, 0x04, 0x01, 0xAA, 0x04, 0x01, 0xBB, 0x00, 0x00];
        assert_eq!(ber_to_der(&ber).unwrap(), [0x04, 0x02, 0xAA, 0xBB]);
        let ber = [0xA0, 0x80, 0x04, 0x01, 0xAA, 0x04, 0x01, 0xBB, 0x00, 0x00];
        assert_eq!(ber_to_der(&ber).unwrap(), [0x80, 0x02, 0xAA, 0xBB]);
        // A context tag holding something other than string chunks stays as is.
        let ber = [0xA0, 0x80, 0x30, 0x00, 0x00, 0x00];
        assert_eq!(ber_to_der(&ber).unwrap(), [0xA0, 0x02, 0x30, 0x00]);
        // A universal SEQUENCE of strings is not a chunked string.
        let ber = [0x30, 0x80, 0x04, 0x01, 0xAA, 0x00, 0x00];
        assert_eq!(ber_to_der(&ber).unwrap(), [0x30, 0x03, 0x04, 0x01, 0xAA]);
    }

    #[test]
    fn malformed_input_is_refused() {
        let cases: &[&[u8]] = &[
            &[],
            &[0x30],
            &[0x30, 0x80, 0x04, 0x01, 0xAA], // no end-of-contents
            &[0x04, 0x80, 0xAA, 0x00, 0x00], // indefinite primitive
            &[0x30, 0x05, 0x04, 0x01, 0xAA], // length past the input
            &[0x30, 0x82, 0x00, 0x03, 0x04, 0x01, 0xAA], // leading zero length
            &[0x30, 0x85, 1, 1, 1, 1, 1],    // length field too long
            &[0x30, 0x03, 0x04, 0x01, 0xAA, 0xFF], // trailing byte
            &[0x30, 0x04, 0x04, 0x01, 0xAA, 0x04], // child overruns parent
            &[0x1F, 0x80, 0x80, 0x80, 0x01, 0x00], // tag too long
        ];
        for case in cases {
            assert!(ber_to_der(case).is_none(), "{case:02x?}");
        }
        let mut deep = Vec::new();
        for _ in 0..18 {
            deep.extend_from_slice(&[0x30, 0x80]);
        }
        for _ in 0..18 {
            deep.extend_from_slice(&[0x00, 0x00]);
        }
        assert!(ber_to_der(&deep).is_none());
    }

    #[test]
    fn streaming_helper_round_trips() {
        let der: Vec<u8> = [vec![
            0x30, 0x0C, 0x80, 0x04, 1, 2, 3, 4, 0x04, 0x04, 5, 6, 7, 8,
        ]]
        .concat();
        let ber = to_streaming_ber(&der);
        assert_ne!(ber, der);
        assert_eq!(ber_to_der(&ber).unwrap(), der);
    }
}
