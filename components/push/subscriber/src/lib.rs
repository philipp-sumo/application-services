/* Handle external Push Subscription Requests.
 * "priviledged" system calls may require additional handling and should be flagged as such.
 */

extern crate serde_json;

extern crate communications;
extern crate crypto;
extern crate storage;

use std::collections::HashMap;

use base64;

use config::PushConfiguration;
use communications::{ConnectHttp, Connection, RegisterResponse, connect};
use crypto::{Crypto, Cryptography, Key, SER_AUTH_LENGTH};
use storage::{Storage, Store};

use push_errors::{self as error, Result};

/*
pub struct SubscriptionKeys {
    pub auth: Vec<u8>,
    pub p256dh: Vec<u8>,
}

// Subscription structure
pub struct Subscription {
    pub channelid: ChannelID,
    pub endpoint: String,
    pub keys: SubscriptionKeys,
}
*/
pub struct PushManager {
    config: PushConfiguration,
    conn: ConnectHttp,
    store: Store,
}

impl PushManager {
    pub fn new(config: PushConfiguration) -> Result<Self> {
        let store = if let Some(ref path) = config.database_path {
            Store::open(path)?
        } else {
            Store::open_in_memory()?
        };
        Ok(PushManager {
            config: config.clone(),
            conn: connect(config)?,
            store
        })
    }

    // XXX: make these trait methods
    // XXX: should be called subscribe?
    pub fn get_subscription_info(&mut self, channel_id: &str, scope: &str) -> Result<RegisterResponse> {
        //let key = self.config.vapid_key;
        let reg_token = self.config.registration_id.clone().unwrap();
        let subscription_key = Crypto::generate_key().unwrap();
        let auth =
            base64::encode_config(&crypto::get_bytes(SER_AUTH_LENGTH)?,
                                  base64::URL_SAFE_NO_PAD);
       let info = self.conn.subscribe(channel_id)?;
        // store the channelid => auth + subscription_key
        let mut record = storage::PushRecord::new(
            &info.uaid,
            &channel_id,
            &info.endpoint,
            scope,
            subscription_key.clone(),
        );
        record.app_server_key = self.config.vapid_key.clone();
        record.native_id = Some(reg_token);
        self.store.put_record(&record)?;
        Ok(info)
    }

    // XXX: maybe -> Result<()> instead
    // XXX: maybe handle channel_id None case separately?
    pub fn unsubscribe(&self, channel_id: Option<&str>) -> Result<bool> {
        let result = self.conn.unsubscribe(channel_id)?;
        self.store.delete_record(self.conn.uaid.as_ref().unwrap(), channel_id.unwrap())?;
        Ok(result)
    }
}

/*
pub trait Subscriber {
    // get a new subscription (including keys, endpoint, etc.)
    // note if this is a "priviledged" system call that does not require additional decryption
    fn get_subscription<S: Storage>(
        storage: S,
        origin_attributes: HashMap<String, String>, // Does this include the origin proper?
        app_server_key: Option<&str>,               // Passed to server.
        registration_key: Option<&str>,             // Local OS push registration ID
        priviledged: bool,                          // Is this a system call / skip encryption?
    ) -> Result<Subscription, SubscriptionError>;

    // Update an existing subscription (change bridge endpoint)
    fn update_subscription<S: Storage>(
        storage: S,
        chid: ChannelID,
        bridge_id: Option<String>,
    ) -> Result<Subscription, SubscriptionError>;

    // remove a subscription
    fn del_subscription<S: Storage>(store: S, chid: ChannelID) -> Result<bool, SubscriptionError>;

    // to_json -> impl Into::<String> for Subscriber...
}

// TODO: transplant the work of our ffi calls into Subscriber
// pass Subscriber around as *the* handle exposed via ffi
// plus the
impl Subscriber for PushManager {
  fn get_subscription<S: Storage>(
        storage: S,
        origin_attributes: HashMap<String, String>,
        app_server_key: Option<&str>,
        registration_key: Option<&str>,
        priviledged: bool,
    ) -> Result<Subscription, SubscriptionError> {
        if let Ok(con) = ConnectHttp::connect::<ConnectHttp>(None) {
            let uaid = con.uaid();
            let chid = storage.generate_channel_id();
            if let Ok(endpoint_data) = con.subscribe(&chid, app_server_key, registration_key) {
                let private_key = Crypto::generate_key().unwrap();
                storage.create_record(
                    &uaid,
                    &chid,
                    origin_attributes,
                    &endpoint_data.endpoint,
                    &con.auth,
                    &private_key,
                    priviledged,
                );
                return Ok(Subscription {
                    channelid: chid,
                    endpoint: endpoint_data.endpoint.clone(),
                    keys: SubscriptionKeys {
                        p256dh: private_key.public.clone(),
                        auth: private_key.auth.clone(),
                    },
                });
            }
        }
        Err(SubscriptionError)
    }

    fn update_subscription<S: Storage>(
        storage: S,
        chid: ChannelID,
        bridge_id: Option<String>,
    ) -> Result<Subscription, SubscriptionError> {
        Err(SubscriptionError)
    }

    // remove a subscription
    fn del_subscription<S: Storage>(store: S, chid: ChannelID) -> Result<bool, SubscriptionError> {
        Ok(false)
    }
}
*/

#[cfg(test)]
mod test {
    use super::*;

    //use serde_json::json;

    // use crypto::{get_bytes, Key};

    const DUMMY_CHID: &'static str = "deadbeef00000000decafbad00000000";
    const DUMMY_UAID: &'static str = "abad1dea00000000aabbccdd00000000";
    // Local test SENDER_ID
    const SENDER_ID: &'static str = "308358850242";
    const SECRET: &'static str = "SuP3rS1kRet";

    #[test]
    fn basic() -> Result<()> {
        let mut pm = PushManager::new(Default::default())?;
        pm.get_subscription_info(DUMMY_CHID, "http://example.com/test-scope")?;
        pm.unsubscribe(Some(DUMMY_CHID))?;
        Ok(())
    }
}
