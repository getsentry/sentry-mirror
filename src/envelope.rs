use hyper::body::Bytes;
use serde_json::Value;
use tracing::{debug, warn};

/// We don't need to fully parse all envelopes.
/// A partial parse of the body into the envelope
/// header and items lets us apply sampling, event id rotation
/// parsing
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Envelope {
    /// The parsed json value of the header.
    pub header: Value,

    /// Collection of items in the envelope.
    pub items: Vec<EnvelopeItem>,
}

impl Envelope {
    /// Convert the envelope into Bytes that contains the envelope header, items and newlines.
    #[allow(dead_code)]
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = vec![];
        let Ok(header_bytes) = serde_json::to_vec(&self.header) else {
            return Bytes::new();
        };
        bytes.extend(header_bytes);
        bytes.extend(b"\n");

        for item in self.items.iter() {
            let item_bytes = item.to_bytes();
            bytes.extend_from_slice(&item_bytes);
            bytes.extend(b"\n");
        }

        Bytes::from(bytes)
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct EnvelopeItem {
    /// The parsed json value of the header.
    pub header: Value,

    /// Bytes of the envelope item.
    pub body: Bytes,
}

impl EnvelopeItem {
    /// Convert the item into bytes that can be added to an envelope bytes.
    pub fn to_bytes(&self) -> Bytes {
        let mut bytes = vec![];
        let Ok(header_bytes) = serde_json::to_vec(&self.header) else {
            return Bytes::new();
        };
        bytes.extend(header_bytes);
        bytes.extend(b"\n");
        bytes.extend(self.body.to_vec());

        Bytes::from(bytes)
    }
}

/// Extract an Envelope out of a byte stream
/// Will return None when no items can be parsed, or the body has no newlines.
#[allow(dead_code)]
pub fn parse(body: &[u8]) -> Option<Envelope> {
    // Split the envelope header off if possible
    let mut body_chunks = body.splitn(2, |&x| x == b'\n');

    // Replace dsn and id values in envelope header
    let envelope_header = match body_chunks.next() {
        Some(bytes) => parse_envelope_header(bytes),
        None => return None,
    };
    let items = parse_envelope_items(body_chunks.next());
    // If we failed to parse any items, we don't want a partial envelope
    if items.is_empty() {
        return None;
    }

    let envelope = Envelope {
        header: envelope_header,
        items,
    };

    Some(envelope)
}

/// Extract and parse the envelope header
fn parse_envelope_header(header: &[u8]) -> Value {
    // envelope headers must be parsable as a string
    let message_header = match String::from_utf8(header.to_vec()) {
        Ok(h) => h,
        Err(e) => {
            warn!("Could not convert envelope header to String {0}", e);

            return Value::Null;
        }
    };
    // envelope headers must be json
    match serde_json::from_str(&message_header) {
        Ok(data) => data,
        Err(_) => Value::Null,
    }
}

/// Extract all the envelope items out of a bytes/none
fn parse_envelope_items(body: Option<&[u8]>) -> Vec<EnvelopeItem> {
    let body = match body {
        Some(body) => body,
        None => return vec![],
    };

    let mut position = 0;
    let mut items: Vec<EnvelopeItem> = vec![];

    // Parse items until we get to the end of the bytestream
    while position < body.len() {
        // Find the end of the item header line (first \n)
        let header_end = match body[position..].iter().position(|&x| x == b'\n') {
            Some(pos) => position + pos,
            None => {
                warn!("Could not find item header line ending");
                return vec![];
            }
        };
        // Item headers must be string + json
        let header_slice = &body[position..header_end];
        let header_str = match String::from_utf8(header_slice.to_vec()) {
            Ok(h) => h,
            Err(e) => {
                warn!("Could not convert item header to String {0}", e);
                return vec![];
            }
        };
        let header_json: Value = match serde_json::from_str(&header_str) {
            Ok(v) => v,
            Err(e) => {
                warn!("Could not convert item header to JSON {0}", e);
                return vec![];
            }
        };

        // Item header and payload are separated by \n
        let data_start = header_end + 1;

        // Read the item length from the header. Or infer the `length` based on newlines.
        // When items don't have `length` defined, payloads are assumed to be on a
        // single line.
        // Ref: https://develop.sentry.dev/sdk/data-model/envelopes/#items
        let length = match header_json.get("length").and_then(|v| v.as_u64()) {
            Some(len) => len as usize,
            None => {
                if let Some(next_line) = body[data_start..].iter().position(|&x| x == b'\n') {
                    next_line
                } else {
                    // Assume we are at the terminal item in the envelope.
                    debug!("Payload missing length, and no newline could be found");
                    body.len() - data_start
                }
            }
        };
        // Calculate the end of the envelope item, and handle int overflows
        let Some(data_end) = data_start.checked_add(length) else {
            warn!("Data length {length} overflows u64");
            return vec![];
        };
        if data_end > body.len() {
            warn!("Data length {length} exceeds remaining bytes");
            return vec![];
        }
        let item_bytes = Bytes::from((body[data_start..data_end]).to_owned());

        // Move to next block (skip past data and the trailing \n)
        position = data_end + 1;

        let item = EnvelopeItem {
            header: header_json,
            body: item_bytes,
        };
        items.push(item);
    }
    items
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_envelope_empty() {
        let body = b"";
        let res = parse(body);
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_envelope_items() {
        let mut body = Vec::new();
        // Envelope header
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"original-id"}"#,
        );
        body.push(b'\n');
        // Feedback item
        body.extend_from_slice(b"{\"type\":\"feedback\",\"length\":40}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"contexts\":{}}\n");
        // Event item
        body.extend_from_slice(b"{\"type\":\"event\",\"length\":43}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"message\":\"test\"}\n");

        let res = parse(body.as_slice());
        assert!(res.is_some());
        let envelope = res.expect("should be some");
        assert_eq!(
            envelope.header.get("dsn").expect("should be there"),
            "https://deadbeef@ingest.sentry.io/123"
        );

        assert_eq!(envelope.items.len(), 2);
        assert_eq!(
            envelope.items[0]
                .header
                .get("type")
                .expect("should be there"),
            "feedback"
        );
        assert_eq!(
            envelope.items[0].body.to_vec(),
            b"{\"event_id\":\"original-id\",\"contexts\":{}}"
        );

        assert_eq!(
            envelope.items[1]
                .header
                .get("type")
                .expect("should be there"),
            "event"
        );
        assert_eq!(
            envelope.items[1].body.to_vec(),
            b"{\"event_id\":\"original-id\",\"message\":\"test\"}"
        );
    }

    #[test]
    fn test_parse_envelope_item_length_overflow_body() {
        let mut body = Vec::new();
        // Envelope header
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"original-id"}"#,
        );
        body.push(b'\n');
        // Feedback item that is ok
        body.extend_from_slice(b"{\"type\":\"feedback\",\"length\":40}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"contexts\":{}}\n");
        // Feedback item with overflow length attribute
        body.extend_from_slice(b"{\"type\":\"feedback\",\"length\":400000}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"contexts\":{}}\n");

        let res = parse(body.as_slice());
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_envelope_item_length_overflow_u64() {
        let mut body = Vec::new();
        // Envelope header
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"original-id"}"#,
        );
        body.push(b'\n');
        // Feedback item that is ok
        body.extend_from_slice(b"{\"type\":\"feedback\",\"length\":40}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"contexts\":{}}\n");
        // Feedback item with overflow length attribute
        body.extend(format!("{{\"type\":\"feedback\",\"length\":{}}}\n", usize::MAX).as_bytes());
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"contexts\":{}}\n");

        let res = parse(body.as_slice());
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_envelope_items_invalid_header() {
        let mut body = Vec::new();
        // Envelope header
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"original-id"}"#,
        );
        body.push(b'\n');
        // Item header is not json
        body.extend_from_slice(b"lol-not-json\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"contexts\":{}}\n");

        let res = parse(body.as_slice());
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_and_to_bytes() {
        let mut body = Vec::new();
        // Envelope header
        body.extend_from_slice(
            br#"{"dsn":"https://deadbeef@ingest.sentry.io/123","event_id":"original-id"}"#,
        );
        body.push(b'\n');
        // Feedback item
        body.extend_from_slice(b"{\"length\":40,\"type\":\"feedback\"}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"contexts\":{}}\n");
        // Event item
        body.extend_from_slice(b"{\"length\":43,\"type\":\"event\"}\n");
        body.extend_from_slice(b"{\"event_id\":\"original-id\",\"message\":\"test\"}\n");

        let parsed = parse(body.as_slice());
        assert!(parsed.is_some());
        let envelope = parsed.expect("should be some");
        let bytes = envelope.to_bytes();
        assert_eq!(bytes.to_vec(), body, "body shape should be preserved");
    }

    #[test]
    fn test_parse_body_invalid_multiline_item() {
        // When items don't have a length, the item is supposed to be all on one line.
        // This test covers non-compliant behavior as the item has no length and is multiline
        let mut body = Vec::new();
        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(b"{\"type\":\"event\"}\n");
        body.extend_from_slice(b"{\"key\":\"value\", \"event_id\":\"replace\"}");
        body.push(b'\n');
        body.extend_from_slice(b"{\"type\":\"feedback\"}\n");
        body.extend_from_slice(b"{\"event_id\":\"replace\", \n");
        body.extend_from_slice(b"\"contexts\":{\"feedback\":{}}}");

        let parsed = parse(body.as_slice());
        assert!(parsed.is_none());
    }

    #[test]
    fn test_parse_body_binary_data() {
        let mut body = Vec::new();

        let binary_data: Vec<u8> = vec![0xFF, 0xFE, 0x00, 0x0A, 0x80, 0x90, 0xA0, 0xB0, 0xC0];
        let binary_header = format!(
            "{{\"type\":\"attachment\",\"length\":{}}}\n",
            binary_data.len()
        );

        body.extend_from_slice(b"{}\n");
        body.extend_from_slice(binary_header.as_bytes());
        body.extend_from_slice(&binary_data);
        body.push(b'\n');

        let parsed = parse(body.as_slice());
        assert!(parsed.is_some());

        let envelope = parsed.expect("should be some");
        assert_eq!(envelope.items.len(), 1);
        assert_eq!(envelope.items[0].header.get("type").unwrap(), "attachment");
        assert_eq!(
            envelope.items[0].body.to_vec(),
            binary_data,
            "should preserve binary data"
        );
    }
}
