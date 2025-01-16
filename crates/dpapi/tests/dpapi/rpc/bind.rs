use std::str::FromStr;

use dpapi::rpc::bind::{ContextElement, ContextResult, ContextResultCode, SyntaxId};
use uuid::Uuid;

test_encoding_decoding! {
    syntax_id,
    SyntaxId,
    SyntaxId {
        uuid: Uuid::from_str("b9785960-524f-11df-8b6d-83dcded72085").expect("valid uuid"),
        version: 1,
        version_minor: 0,
    },
    [96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0]
}

test_encoding_decoding! {
    context_element,
    ContextElement,
    ContextElement {
        context_id: 0,
        abstract_syntax: SyntaxId {
            uuid: Uuid::from_str("b9785960-524f-11df-8b6d-83dcded72085").expect("valid uuid"),
            version: 1,
            version_minor: 0,
        },
        transfer_syntaxes: vec![
            SyntaxId {
                uuid: Uuid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").expect("valid uuid"),
                version: 1,
                version_minor: 0,
            }
        ],
    },
    [0, 0, 1, 0, 96, 89, 120, 185, 79, 82, 223, 17, 139, 109, 131, 220, 222, 215, 32, 133, 1, 0, 0, 0, 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0]
}

test_encoding_decoding! {
    context_result,
    ContextResult,
    ContextResult {
        result: ContextResultCode::Acceptance,
        reason: 0,
        syntax: Uuid::from_str("71710533-beba-4937-8319-b5dbef9ccc36").unwrap(),
        syntax_version: 1,
    },
    [0, 0, 0, 0, 51, 5, 113, 113, 186, 190, 55, 73, 131, 25, 181, 219, 239, 156, 204, 54, 1, 0, 0, 0]
}
