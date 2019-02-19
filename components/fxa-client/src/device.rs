/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

pub use crate::http_client::{
    DeviceLocation as Location, DeviceType as Type, GetDeviceResponse as Device, PushSubscription,
};
use crate::{
    commands::send_tab::{self, SendTabPayload},
    errors::*,
    http_client::{
        CommandData, DeviceUpdateRequest, DeviceUpdateRequestBuilder, PendingCommand,
        UpdateDeviceResponse,
    },
    AccountEvent, FirefoxAccount,
};
use std::collections::HashMap;

impl FirefoxAccount {
    /// Fetches the list of devices from the current account including
    /// the current one.
    pub fn get_devices(&mut self) -> Result<Vec<Device>> {
        let access_token = self.get_refresh_token()?;
        self.client.devices(&self.state.config, &access_token)
    }

    pub(crate) fn invoke_command(
        &mut self,
        command: &str,
        target: &Device,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let access_token = self.get_refresh_token()?;
        self.client.invoke_command(
            &self.state.config,
            &access_token,
            command,
            &target.id,
            payload,
        )
    }

    /// Poll and handle any pending available command. This should be called
    /// semi-regularly as the main method of commands delivery (push)
    /// can sometimes be unreliable on mobile devices.
    pub fn poll_remote_commands(&mut self) -> Result<Vec<AccountEvent>> {
        let last_command_index = self.state.last_handled_command.unwrap_or(0);
        let refresh_token = self.get_refresh_token()?;
        // We increment last_command_index by 1 because the server response includes the current index.
        let pending_commands = self.client.pending_commands(
            &self.state.config,
            refresh_token,
            last_command_index + 1,
            None,
        )?;
        if pending_commands.messages.len() == 0 {
            return Ok(Vec::new());
        }
        log::info!("Handling {} messages", pending_commands.messages.len());
        let account_events = self.handle_commands(pending_commands.messages)?;
        self.state.last_handled_command = Some(pending_commands.index);
        self.maybe_call_persist_callback();
        Ok(account_events)
    }

    fn handle_commands(&mut self, messages: Vec<PendingCommand>) -> Result<Vec<AccountEvent>> {
        let mut account_events: Vec<AccountEvent> = Vec::with_capacity(messages.len());
        let commands: Vec<_> = messages.into_iter().map(|m| m.data).collect();
        let devices = self.get_devices()?;
        for data in commands {
            match self.handle_command(data, &devices) {
                Ok((sender, tab)) => account_events.push(AccountEvent::TabReceived((sender, tab))),
                Err(e) => log::error!("Error while processing command: {}", e),
            };
        }
        Ok(account_events)
    }

    // Returns SendTabPayload for now because we only receive send-tab commands and
    // it's way easier, but should probably return AccountEvent or similar in the future.
    fn handle_command(
        &mut self,
        command_data: CommandData,
        devices: &[Device],
    ) -> Result<(Option<Device>, SendTabPayload)> {
        let sender = command_data
            .sender
            .and_then(|s| devices.iter().find(|i| i.id == s).map(|x| x.clone()));
        match command_data.command.as_str() {
            send_tab::COMMAND_NAME => self.handle_send_tab_command(sender, command_data.payload),
            _ => Err(ErrorKind::UnknownCommand(command_data.command).into()),
        }
    }

    pub fn set_display_name(&self, name: &str) -> Result<UpdateDeviceResponse> {
        let update = DeviceUpdateRequestBuilder::new().display_name(name).build();
        self.update_device(update)
    }

    pub fn clear_display_name(&self) -> Result<UpdateDeviceResponse> {
        let update = DeviceUpdateRequestBuilder::new()
            .clear_display_name()
            .build();
        self.update_device(update)
    }

    pub fn set_push_subscription(
        &self,
        push_subscription: PushSubscription,
    ) -> Result<UpdateDeviceResponse> {
        let update = DeviceUpdateRequestBuilder::new()
            .push_subscription(push_subscription)
            .build();
        self.update_device(update)
    }

    // TODO: use the PATCH endpoint instead of overwritting everything.
    #[allow(dead_code)]
    pub(crate) fn register_command(
        &self,
        command: &str,
        value: &str,
    ) -> Result<UpdateDeviceResponse> {
        let mut commands = HashMap::new();
        commands.insert(command.to_owned(), value.to_owned());
        let update = DeviceUpdateRequestBuilder::new()
            .available_commands(commands)
            .build();
        self.update_device(update)
    }

    // TODO: this currently deletes every command registered.
    #[allow(dead_code)]
    pub(crate) fn unregister_command(&self, _: &str) -> Result<UpdateDeviceResponse> {
        let commands = HashMap::new();
        let update = DeviceUpdateRequestBuilder::new()
            .available_commands(commands)
            .build();
        self.update_device(update)
    }

    #[allow(dead_code)]
    pub(crate) fn clear_commands(&self) -> Result<UpdateDeviceResponse> {
        let update = DeviceUpdateRequestBuilder::new()
            .clear_available_commands()
            .build();
        self.update_device(update)
    }

    fn update_device(&self, update: DeviceUpdateRequest) -> Result<UpdateDeviceResponse> {
        let refresh_token = self.get_refresh_token()?;
        self.client
            .update_device(&self.state.config, refresh_token, update)
    }
}
