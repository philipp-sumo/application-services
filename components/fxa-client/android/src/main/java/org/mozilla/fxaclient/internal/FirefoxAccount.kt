/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.fxaclient.internal

/**
 * FirefoxAccount represents the authentication state of a client.
 */
class FirefoxAccount : RustObject {

    internal constructor(rawPointer: FxaHandle): super(rawPointer)

    /**
     * Create a FirefoxAccount using the given config.
     *
     * This does not make network requests, and can be used on the main thread.
     */
    constructor(config: Config)
    : this(unlockedRustCall { e ->
        FxaClient.INSTANCE.fxa_new(config.contentUrl, config.clientId, config.redirectUri, e)
    })

    override fun destroy(p: Long) {
        unlockedRustCall { err ->
            FxaClient.INSTANCE.fxa_free(p, err)
        }
    }

    /**
     * Constructs a URL used to begin the OAuth flow for the requested scopes and keys.
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @param scopes List of OAuth scopes for which the client wants access
     * @param wantsKeys Fetch keys for end-to-end encryption of data from Mozilla-hosted services
     * @return String that resolves to the flow URL when complete
     */
    fun beginOAuthFlow(scopes: Array<String>, wantsKeys: Boolean): String {
        val scope = scopes.joinToString(" ")
        return rustCall { e ->
            FxaClient.INSTANCE.fxa_begin_oauth_flow(validHandle(), scope, wantsKeys, e)
        }.getAndConsumeString()
    }

    /**
     * Begins the pairing flow.
     *
     * This performs network requests, and should not be used on the main thread.
     */
    fun beginPairingFlow(pairingUrl: String, scopes: Array<String>): String {
        val scope = scopes.joinToString(" ")
        return rustCall { e ->
            FxaClient.INSTANCE.fxa_begin_pairing_flow(validHandle(), pairingUrl, scope, e)
        }.getAndConsumeString()
    }

    /**
     * Fetches the profile object for the current client either from the existing cached account,
     * or from the server (requires the client to have access to the profile scope).
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @param ignoreCache Fetch the profile information directly from the server
     * @return [Profile] representing the user's basic profile info
     * @throws FxaException.Unauthorized We couldn't find any suitable access token to make that call.
     * The caller should then start the OAuth Flow again with the "profile" scope.
     */
    fun getProfile(ignoreCache: Boolean): Profile {
        val profileBuffer = rustCall { e ->
            FxaClient.INSTANCE.fxa_profile(validHandle(), ignoreCache, e)
        }
        try {
            val p = MsgTypes.Profile.parseFrom(profileBuffer.asCodedInputStream()!!)
            return Profile.fromMessage(p)
        } finally {
            FxaClient.INSTANCE.fxa_bytebuffer_free(profileBuffer)
        }
    }

    /**
     * Convenience method to fetch the profile from a cached account by default, but fall back
     * to retrieval from the server.
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @return [Profile] representing the user's basic profile info
     * @throws FxaException.Unauthorized We couldn't find any suitable access token to make that call.
     * The caller should then start the OAuth Flow again with the "profile" scope.
     */
    fun getProfile(): Profile {
        return getProfile(false)
    }

    /**
     * Fetches the token server endpoint, for authentication using the SAML bearer flow.
     *
     * This does not make network requests, and can be used on the main thread.
     */
    fun getTokenServerEndpointURL(): String {
        return rustCall { e ->
            FxaClient.INSTANCE.fxa_get_token_server_endpoint_url(validHandle(), e)
        }.getAndConsumeString()
    }

    /**
     * Fetches the connection success url.
     *
     * This does not make network requests, and can be used on the main thread.
     */
    fun getConnectionSuccessURL(): String {
        return rustCall { e ->
            FxaClient.INSTANCE.fxa_get_connection_success_url(validHandle(), e)
        }.getAndConsumeString()
    }

    /**
     * Authenticates the current account using the code and state parameters fetched from the
     * redirect URL reached after completing the sign in flow triggered by [beginOAuthFlow].
     *
     * Modifies the FirefoxAccount state.
     *
     * This performs network requests, and should not be used on the main thread.
     */
    fun completeOAuthFlow(code: String, state: String) {
        rustCall { e ->
            FxaClient.INSTANCE.fxa_complete_oauth_flow(validHandle(), code, state, e)
        }
    }

    /**
     * Tries to fetch an access token for the given scope.
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @param scope Single OAuth scope (no spaces) for which the client wants access
     * @return [AccessTokenInfo] that stores the token, along with its scopes and keys when complete
     * @throws FxaException.Unauthorized We couldn't provide an access token
     * for this scope. The caller should then start the OAuth Flow again with
     * the desired scope.
     */
    fun getAccessToken(scope: String): AccessTokenInfo {
        return AccessTokenInfo(rustCall { e ->
            FxaClient.INSTANCE.fxa_get_access_token(validHandle(), scope, e)
        })
    }

    /**
     * Saves the current account's authentication state as a JSON string, for persistence in
     * the Android KeyStore/shared preferences. The authentication state can be restored using
     * [FirefoxAccount.fromJSONString].
     *
     * This does not make network requests, and can be used on the main thread.
     *
     * @return String containing the authentication details in JSON format
     */
    fun toJSONString(): String {
        return rustCall { e ->
            FxaClient.INSTANCE.fxa_to_json(validHandle(), e)
        }.getAndConsumeString()
    }

    /**
     * Update the push subscription details for the current device.
     * This needs should be called every time a push subscription is modified or expires.
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @param endpoint Push callback URL
     * @param endpoint Public key used to encrypt push payloads
     * @param endpoint Auth key used to encrypt push payloads
     */
    fun setDevicePushSubscription(endpoint: String, publicKey: String, authKey: String) {
        rustCall { e ->
            FxaClient.INSTANCE.fxa_set_push_subscription(validHandle(), endpoint, publicKey, authKey, e)
        }
    }

    /**
     * Update the display name (as shown in the FxA device manager, or the Send Tab target list)
     * for the current device.
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @param displayName The current device display name
     */
    fun setDeviceDisplayName(displayName: String) {
        rustCall { e ->
            FxaClient.INSTANCE.fxa_set_display_name(validHandle(), displayName, e)
        }
    }

    /**
     * Retrieves the list of the connected devices in the current account, including the current one.
     *
     * This performs network requests, and should not be used on the main thread.
     */
    fun getDevices(): Array<Device> {
        val devicesBuffer = rustCall { e ->
            FxaClient.INSTANCE.fxa_get_devices(validHandle(), e)
        }
        try {
            val devices = MsgTypes.Devices.parseFrom(devicesBuffer.asCodedInputStream()!!)
            return Device.fromCollectionMessage(devices)
        } finally {
            FxaClient.INSTANCE.fxa_bytebuffer_free(devicesBuffer)
        }
    }

    /**
     * Retrieves any pending commands for the current device.
     * This should be called semi-regularly as the main method of commands delivery (push)
     * can sometimes be unreliable on mobile devices.
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @return A collection of [AccountEvent] that should be handled by the caller.
     */
    fun pollRemoteCommands(): Array<AccountEvent> {
        val eventsBuffer = rustCall { e ->
            FxaClient.INSTANCE.fxa_poll_remote_commands(validHandle(), e)
        }
        try {
            val events = MsgTypes.AccountEvents.parseFrom(eventsBuffer.asCodedInputStream()!!)
            return AccountEvent.fromCollectionMessage(events)
        } finally {
            FxaClient.INSTANCE.fxa_bytebuffer_free(eventsBuffer)
        }
    }

    /**
     * Handle any incoming push message payload coming from the Firefox Accounts
     * servers.
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @return A collection of [AccountEvent] that should be handled by the caller.
     */
    fun handlePushMessage(payload: String): Array<AccountEvent> {
        val eventsBuffer = rustCall { e ->
            FxaClient.INSTANCE.fxa_handle_push_message(validHandle(), payload, e)
        }
        try {
            val events = MsgTypes.AccountEvents.parseFrom(eventsBuffer.asCodedInputStream()!!)
            return AccountEvent.fromCollectionMessage(events)
        } finally {
            FxaClient.INSTANCE.fxa_bytebuffer_free(eventsBuffer)
        }
    }

    /**
     * Ensure the current device "Send Tab" commands has been registered with the server.
     * This method should be called once per "device lifetime" after the Sync Keys have been
     * obtained and called again if they change.
     *
     * This performs network requests, and should not be used on the main thread.
     */
    fun ensureSendTabRegistered() {
        rustCall { e ->
            FxaClient.INSTANCE.fxa_ensure_send_tab_registered(validHandle(), e)
        }
    }

    /**
     * Send a single tab to another device identified by its device ID.
     *
     * This performs network requests, and should not be used on the main thread.
     *
     * @param targetDeviceId The target Device ID
     * @param title The document title of the tab being sent
     * @param url The url of the tab being sent
     */
    fun sendSingleTab(targetDeviceId: String, title: String, url: String) {
        rustCall { e ->
            FxaClient.INSTANCE.fxa_send_tab(validHandle(), targetDeviceId, title, url, e)
        }
    }

    companion object {

        /**
         * Restores the account's authentication state from a JSON string produced by
         * [FirefoxAccount.toJSONString].
         *
         * This does not make network requests, and can be used on the main thread.
         *
         * @return [FirefoxAccount] representing the authentication state
         */
        fun fromJSONString(json: String): FirefoxAccount {
            return FirefoxAccount(unlockedRustCall { e ->
                FxaClient.INSTANCE.fxa_from_json(json, e)
            })
        }
    }
}
