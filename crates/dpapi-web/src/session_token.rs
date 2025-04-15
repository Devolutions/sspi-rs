use std::io::Error;
use std::sync::Arc;

use dpapi_transport::GetSessionTokenFn;
use url::Url;
use uuid::Uuid;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;

pub fn session_token_fn(get_session_token: Arc<js_sys::Function>) -> Box<GetSessionTokenFn> {
    Box::new(move |session_id: Uuid, destination: Url| {
        let get_session_token = Arc::clone(&get_session_token);
        Box::pin(async move {
            let session_id = JsValue::from_str(&session_id.to_string());
            let destination = JsValue::from_str(destination.as_str());

            let promise = get_session_token
                .call2(&JsValue::NULL, &session_id, &destination)
                .map_err(|err| Error::other(format!("failed to obtain the session token: {:?}", err)))?
                .dyn_into::<js_sys::Promise>()
                .map_err(|err| Error::other(format!("failed to obtain the session token: {:?}", err)))?;

            let session_token = JsFuture::from(promise)
                .await
                .map_err(|err| Error::other(format!("failed to obtain the session token: {:?}", err)))?;

            Ok(session_token
                .as_string()
                .ok_or_else(|| Error::other("obtained session token is not a String"))?)
        })
    })
}
