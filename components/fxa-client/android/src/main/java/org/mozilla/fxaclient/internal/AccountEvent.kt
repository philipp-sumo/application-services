/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.fxaclient.internal

data class TabData(
    val title: String,
    val url: String
)

sealed class AccountEvent {
    class TabReceived(val from: Device?, val entries: Array<TabData>) : AccountEvent()

    companion object {
        private fun fromMessage(msg: MsgTypes.AccountEvent): AccountEvent {
            when (msg.type) {
                MsgTypes.AccountEvent.AccountEventType.TAB_RECEIVED -> {
                    val data = msg.tabReceivedData
                    return TabReceived(
                            from = if (data.hasFrom()) Device.fromMessage(data.from) else null,
                            entries = data.entriesList.map {
                                TabData(title = it.title, url = it.url)
                            }.toTypedArray()
                    )
                }
            }
        }
        internal fun fromCollectionMessage(msg: MsgTypes.AccountEvents): Array<AccountEvent> {
            return msg.eventsList.map {
                AccountEvent.fromMessage(it)
            }.toTypedArray()
        }
    }
}
