/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.client_auth;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Locale;
import java.util.UUID;

public class DeviceIdentity {
    private UUID deviceId;
    private String deviceLabel;
    private long createdAt;

    public DeviceIdentity() {
    }

    public DeviceIdentity(UUID deviceId, String deviceLabel, long createdAt) {
        this.deviceId = deviceId;
        this.deviceLabel = deviceLabel;
        this.createdAt = createdAt;
    }

    public static DeviceIdentity create(UUID deviceId, String playerName) {
        return new DeviceIdentity(deviceId, defaultLabel(playerName), System.currentTimeMillis());
    }

    public static String defaultLabel(String playerName) {
        String hostName = null;
        try {
            hostName = InetAddress.getLocalHost().getHostName();
        } catch (UnknownHostException ignored) {
        }
        String suffix = UUID.randomUUID().toString().substring(0, 6).toLowerCase(Locale.ROOT);
        if (hostName != null && !hostName.isBlank()) {
            return hostName + "-" + suffix;
        }
        return playerName + "-device-" + suffix;
    }

    public UUID getDeviceId() {
        return deviceId;
    }

    public String getDeviceLabel() {
        return deviceLabel;
    }

    public long getCreatedAt() {
        return createdAt;
    }
}
