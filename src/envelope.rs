
use hyper::body::Bytes;
use serde_json::Value;
use tracing::{debug, warn};
/*
 *
Envelope
- header_json
- header_bytes
- body_bytes
- vec<envelopeitem>

EnvelopeItem
- header_json
- header_bytes
- item_bytes
*/

/// We don't need to fully parse all envelopes.
/// A partial parse of the body into the envelope
/// header and items lets us apply sampling, event id rotation
/// parsing 
#[derive(Debug, Clone)]
pub struct Envelope {
    pub header: Value,
    pub items: Vec<EnvelopeItem>,
}

#[derive(Debug, Clone)]
pub struct EnvelopeItem {
    pub header: Value,
    pub body: Bytes,
}

/// Extract an Envelope out of a byte stream
pub fn parse(body: &[u8]) -> Option<Envelope> {
    // Split the envelope header off if possible
    let mut body_chunks = body.splitn(2, |&x| x == b'\n');

    // Replace dsn and id values in envelope header
    let envelope_header = match body_chunks.next() {
        Some(bytes) => parse_envelope_header(bytes),
        None => return None,
    };
    let items = parse_envelope_items(body_chunks.next());
    let envelope = Envelope {
        header: envelope_header,
        items,
    };

    Some(envelope)
}

fn parse_envelope_header(header: &[u8]) -> Value {
    // We don't want to copy the entire body to String as
    // replays have blobs in them, and we only need the header.
    let message_header = match String::from_utf8(header.to_vec()) {
        Ok(h) => h,
        Err(e) => {
            warn!("Could not convert envelope header to String {0}", e);

            return Value::Null;
        }
    };
    match serde_json::from_str(&message_header) {
        Ok(data) => data,
        Err(_) => Value::Null,
    }
}

fn parse_envelope_items(body: Option<&[u8]>) -> Vec<EnvelopeItem> {
    let body = match body {
        Some(body) => body,
        None => return vec![],
    };

    let mut position = 0;
    let mut items: Vec<EnvelopeItem> = vec![];

    // Iterate over item blocks in envelope
    while position < body.len() {
        // Find the end of the item header line (first \n)
        let header_end = match body[position..].iter().position(|&x| x == b'\n') {
            Some(pos) => position + pos,
            None => {
                warn!("Could not find item header line ending");
                return items;
            }
        };

        let header_slice = &body[position..header_end];
        let header_str = match String::from_utf8(header_slice.to_vec()) {
            Ok(h) => h,
            Err(e) => {
                warn!("Could not convert item header to String {0}", e);
                return items;
            }
        };
        let header_json: Value = match serde_json::from_str(&header_str) {
            Ok(v) => v,
            Err(e) => {
                warn!("Could not convert item header to JSON {0}", e);
                return items;
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
        // Position of where the current item ends.
        let data_end = data_start + length;
        if data_end > body.len() {
            warn!("Data length {length} exceeds remaining bytes");
            return items;
        }
        let item_bytes = Bytes::from((body[data_start..data_end]).to_owned());

        // Move to next block (skip past data and the trailing \n)
        position = data_end + 1;

        let item = EnvelopeItem {header: header_json, body: item_bytes};
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
        assert!(res.is_some());
        let envelope = res.expect("should be some");
        assert_eq!(envelope.header, Value::Null);
        assert_eq!(envelope.items.len(), 0);
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
        assert_eq!(envelope.header.get("dsn").expect("should be there"), "https://deadbeef@ingest.sentry.io/123");

        assert_eq!(envelope.items.len(), 2);
        assert_eq!(envelope.items[0].header.get("type").expect("should be there"), "feedback");
        assert_eq!(envelope.items[0].body.to_vec(), b"{\"event_id\":\"original-id\",\"contexts\":{}}");

        assert_eq!(envelope.items[1].header.get("type").expect("should be there"), "event");
        assert_eq!(envelope.items[1].body.to_vec(), b"{\"event_id\":\"original-id\",\"message\":\"test\"}");
    }
}
