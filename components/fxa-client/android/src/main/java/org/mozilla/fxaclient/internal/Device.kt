/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package org.mozilla.fxaclient.internal

data class Device(
    val id: String,
    val displayName: String,
    val deviceType: Device.Type,
    val pushSubscription: Device.PushSubscription?,
    val pushEndpointExpired: Boolean,
    val isCurrentDevice: Boolean,
    val location: Device.Location,
    val lastAccessTime: Long?
) {
    enum class Type {
        DESKTOP,
        MOBILE,
        UNKNOWN;

        companion object {
            internal fun fromMessage(msg: MsgTypes.Device.Type): Type {
                return when (msg) {
                    MsgTypes.Device.Type.DESKTOP -> DESKTOP
                    MsgTypes.Device.Type.MOBILE -> MOBILE
                    else -> UNKNOWN
                }
            }
        }
    }
    data class PushSubscription(
        val endpoint: String,
        val publicKey: String,
        val authKey: String
    ) {
        companion object {
            internal fun fromMessage(msg: MsgTypes.Device.PushSubscription): PushSubscription {
                return PushSubscription(
                        endpoint = msg.endpoint,
                        publicKey = msg.publicKey,
                        authKey = msg.authKey
                )
            }
        }
    }
    data class Location(
        val city: String,
        val country: String,
        val state: String,
        val stateCode: String
    ) {
        companion object {
            internal fun fromMessage(msg: MsgTypes.Device.Location): Location {
                return Location(
                        city = msg.city,
                        country = msg.country,
                        state = msg.state,
                        stateCode = msg.stateCode
                )
            }
        }
    }
    companion object {
        internal fun fromMessage(msg: MsgTypes.Device): Device {
            return Device(
                    id = msg.id,
                    displayName = msg.displayName,
                    deviceType = Device.Type.fromMessage(msg.type),
                    pushSubscription = if (msg.hasPushSubscription()) Device.PushSubscription.fromMessage(msg.pushSubscription) else null,
                    pushEndpointExpired = msg.pushEndpointExpired,
                    isCurrentDevice = msg.isCurrentDevice,
                    location = Device.Location.fromMessage(msg.location),
                    lastAccessTime = if (msg.hasLastAccessTime()) msg.lastAccessTime else null
            )
        }
        internal fun fromCollectionMessage(msg: MsgTypes.Devices): Array<Device> {
            return msg.devicesList.map {
                Device.fromMessage(it)
            }.toTypedArray()
        }
    }
}
