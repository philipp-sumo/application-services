/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use ffi_support::{
    define_box_destructor, define_handle_map_deleter, define_string_destructor, rust_str_from_c,
    rust_string_from_c, ConcurrentHandleMap, ExternError,
};
use sync15::telemetry;

use base64;
use serde_json::{self, json};

use std::os::raw::c_char;

use communications::{connect, ConnectHttp, Connection};
use config::PushConfiguration;
use crypto::{get_bytes, Crypto, Cryptography, Key, SER_AUTH_LENGTH};
use storage::Storage;

// indirection to help `?` figure out the target error type
fn parse_url(url: &str) -> sync15::Result<url::Url> {
    Ok(url::Url::parse(url)?)
}

#[no_mangle]
pub extern "C" fn push_enable_logcat_logging() {
    #[cfg(target_os = "android")]
    {
        let _ = std::panic::catch_unwind(|| {
            android_logger::init_once(
                android_logger::Filter::default().with_min_level(log::Level::Debug),
                Some("libpush_ffi"),
            );
            log::debug!("Android logging should be hooked up!")
        });
    }
}

lazy_static::lazy_static! {
    static ref CONNECTIONS: ConcurrentHandleMap<ConnectHttp> = ConcurrentHandleMap::new();
}

/// Instantiate a Http connection. Returned connection must be freed with
/// `push_connection_destroy`. Returns null and logs on errors (for now).
#[no_mangle]
pub unsafe extern "C" fn push_connection_new(
    server_host: *const c_char,
    socket_protocol: *const c_char,
    bridge_type: *const c_char,
    registration_id: *const c_char,
    sender_id: *const c_char,
    database_path: *const c_char,
    error: &mut ExternError,
) -> u64 {
    log::debug!(
        "push_connection_new {:?} {:?} -> {:?} {:?}=>{:?}",
        socket_protocol,
        server_host,
        bridge_type,
        sender_id,
        registration_id
    );
    // return this as a reference to the map since that map contains the actual handles that rust uses.
    // see ffi layer for details.
    CONNECTIONS.insert_with_result(error, || {
        let host = ffi_support::rust_string_from_c(server_host);
        let protocol = ffi_support::opt_rust_string_from_c(socket_protocol);
        let reg_id = ffi_support::opt_rust_string_from_c(registration_id);
        let bridge = ffi_support::opt_rust_string_from_c(bridge_type);
        let sender = ffi_support::rust_string_from_c(sender_id);
        let db_path = ffi_support::opt_rust_string_from_c(database_path);
        let config = PushConfiguration {
            server_host: host,
            http_protocol: protocol,
            bridge_type: bridge,
            registration_id: reg_id,
            sender_id: sender,
            database_path: db_path,
            ..Default::default()
        };
        connect(config).into()
    })
}

// Add a subscription
/// Errors are logged.
#[no_mangle]
pub unsafe extern "C" fn push_get_subscription_info(
    handle: u64,
    channel_id: *const c_char,
    error: &mut ExternError,
) -> *mut c_char {
    log::debug!("push_get_subscription");
    CONNECTIONS.call_with_result_mut(error, handle, |conn| {
        let options = conn.options.clone();
        let channel = ffi_support::rust_str_from_c(channel_id);
        let key = options.vapid_key;
        let reg_token = options.registration_id?;
        let subscription_key = Crypto::generate_key().unwrap();
        let auth =
            base64::encode_config(&crypto::get_bytes(SER_AUTH_LENGTH)?,
                                  base64::URL_SAFE_NO_PAD);
        // Don't auto add the subscription to the db.
        // (endpoint updates also call subscribe and should be lighter weight)
        let info = conn.subscribe(channel).unwrap();
        // store the channelid => auth + subscription_key
        let mut record = storage::PushRecord::new(
            &info.uaid,
            &channel,
            &info.endpoint,
            "",
            subscription_key.clone(),
        );
        record.app_server_key = options.vapid_key.clone();
        record.native_id = Some(reg_token);
        conn.database.put_record(&record)?;
        let subscription_info = json!({
            "endpoint": info.endpoint,
            "keys": {
                "auth": auth,
                "p256dh": base64::encode_config(&subscription_key.public,
                                                base64::URL_SAFE_NO_PAD)
            }
        });
        return Ok(subscription_info.to_string());
    })
}

// Unsubscribe a channel
#[no_mangle]
pub unsafe extern "C" fn push_unsubscribe(
    handle: u64,
    channel_id: *const c_char,
    error: &mut ExternError,
) -> u8 {
    log::debug!("push_unsubscribe");
    CONNECTIONS.call_with_result_mut(error, handle, |conn| {
        let channel = ffi_support::opt_rust_str_from_c(channel_id);
        Ok(conn.unsubscribe(channel).unwrap())
    })
}

// Update the OS token
#[no_mangle]
pub unsafe extern "C" fn push_update(
    handle: u64,
    new_token: *const c_char,
    error: &mut ExternError,
) -> u8 {
    log::debug!("push_update");
    CONNECTIONS.call_with_result_mut(error, handle, |conn| {
        let token = ffi_support::opt_rust_str_from_c(new_token)?;
        Ok(conn.update(&token).unwrap())
    })
}

// verify connection using channel list
// Returns a JSON containing the new channelids => endpoints
// NOTE: AC should notify processes associated with channelIDs of new endpoint
#[no_mangle]
pub unsafe extern "C" fn push_verify_connection(
    handle: u64,
    error: &mut ExternError,
) -> *mut c_char {
    log::debug!("push_verify");
    CONNECTIONS.call_with_result_mut(error, handle, |conn| {
        let known_channels = conn.database.get_channel_list(&conn.uaid.unwrap());
        let options = conn.options.clone();
        if let Ok(r) = conn.verify_connection() {
            if r == false {
                if let Ok(new_endpoints) = conn.regenerate_endpoints() {
                    return serde_json::to_string(&new_endpoints).into()
                }
            }
        }
        Ok(String::from(""))
    })
}

#[no_mangle]
pub unsafe extern "C" fn push_decrypt(
    handle: u64,
    chid: *const c_char,
    body: *const c_char,
    encoding: *const c_char,
    salt: *const c_char,
    dh: *const c_char,
    error: &mut ExternError,
) -> *mut c_char {
    log::debug!("push_decrypt");
    CONNECTIONS.call_with_result_mut(error, handle, |conn| {
        let r_chid = ffi_support::rust_str_from_c(chid);
        let r_body = ffi_support::rust_str_from_c(body).to_owned().as_bytes().to_vec();
        let r_encoding = ffi_support::rust_str_from_c(encoding);
        let r_salt: Option<Vec<u8>> =
            ffi_support::opt_rust_str_from_c(salt).map(|v| v.as_bytes().to_vec());
        let r_dh: Option<Vec<u8>> =
            ffi_support::opt_rust_str_from_c(dh).map(|v| v.as_bytes().to_vec());
        let uaid = conn.uaid.unwrap();
        if let Some(push_record) = conn.database.get_record(&uaid, r_chid)? {
            let key = crypto::Key::deserialize(push_record.key)?;
            return crypto::Crypto::decrypt(&key, r_body, r_encoding, r_salt, r_dh);
        } else {
            log::error!("No record for uaid:chid {:?}:{:?}", conn.uaid, chid);
            // TODO: Send Unsubscription?
            // TODO: How to declare error response?
            Ok(String::from("").as_bytes().to_vec())
        }
    })
}
// TODO: modify these to be relevant.

define_string_destructor!(push_destroy_string);
define_handle_map_deleter!(CONNECTIONS, push_connection_destroy);
// define_box_destructor!(PlacesInterruptHandle, places_interrupt_handle_destroy);
