/* Handle external Push Subscription Requests.
 * "priviledged" system calls may require additional handling and should be flagged as such.
 */

extern crate serde_json;

extern crate communications;
extern crate crypto;
extern crate storage;

use std::collections::HashMap;


use config::PushConfiguration;
use communications::{ConnectHttp, Connection, RegisterResponse, connect};
use crypto::{Crypto, Cryptography, Key};
use storage::{Storage, Store};

use push_errors::{self as error, Result};

pub struct PushManager {
    config: PushConfiguration,
    pub conn: ConnectHttp,
    pub store: Store,
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
    pub fn subscribe(&mut self, channel_id: &str, scope: &str) -> Result<(RegisterResponse, Key)> {
        //let key = self.config.vapid_key;
        let reg_token = self.config.registration_id.clone().unwrap();
        let subscription_key = Crypto::generate_key().unwrap();
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
        // TODO: just return Record
        Ok((info, subscription_key))
    }

    // XXX: maybe -> Result<()> instead
    // XXX: maybe handle channel_id None case separately?
    pub fn unsubscribe(&self, channel_id: Option<&str>) -> Result<bool> {
        let result = self.conn.unsubscribe(channel_id)?;
        self.store.delete_record(self.conn.uaid.as_ref().unwrap(), channel_id.unwrap())?;
        Ok(result)
    }

    pub fn update(&mut self, new_token: &str) -> error::Result<bool> {
        let result = self.conn.update(&new_token)?;
        self.store.update_native_id(self.conn.uaid.as_ref().unwrap(), new_token)?;
        Ok(result)
    }

    pub fn verify_connection(&self) -> error::Result<bool> {
        let channels = self.store.get_channel_list(self.conn.uaid.as_ref().unwrap())?;
        self.conn.verify_connection(&channels)
    }

    /// Fetch new endpoints for a list of channels.
    pub fn regenerate_endpoints(
        &mut self,
    ) -> error::Result<HashMap<String, String>> {
        let uaid = self.conn.uaid.clone().unwrap();
        let channels = self.store.get_channel_list(&uaid)?;
        let mut results: HashMap<String, String> = HashMap::new();
        for channel in channels {
            let info = self.conn.subscribe(
                &channel)?;
            self.store.update_endpoint(&uaid, &channel, &info.endpoint)?;
            results.insert(channel.clone(), info.endpoint);
        }
        Ok(results)
    }
}


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
        //pm.subscribe(DUMMY_CHID, "http://example.com/test-scope")?;
        //pm.unsubscribe(Some(DUMMY_CHID))?;
        Ok(())
    }
}
