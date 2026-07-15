/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.client_auth;

import io.netty.buffer.Unpooled;
import net.minecraft.network.FriendlyByteBuf;

public class DeviceRegistrationRequest {
    private final String deviceLabel;
    private final byte[] publicKey;

    public DeviceRegistrationRequest(String deviceLabel, byte[] publicKey) {
        this.deviceLabel = deviceLabel;
        this.publicKey = publicKey;
    }

    public byte[] encode() {
        FriendlyByteBuf buf = new FriendlyByteBuf(Unpooled.buffer());
        buf.writeUtf(deviceLabel);
        buf.writeByteArray(publicKey);
        byte[] data = new byte[buf.readableBytes()];
        buf.readBytes(data);
        return data;
    }

    public static DeviceRegistrationRequest decode(byte[] payload) {
        FriendlyByteBuf buf = new FriendlyByteBuf(Unpooled.wrappedBuffer(payload));
        return new DeviceRegistrationRequest(buf.readUtf(), buf.readByteArray());
    }

    public String getDeviceLabel() {
        return deviceLabel;
    }

    public byte[] getPublicKey() {
        return publicKey;
    }
}
