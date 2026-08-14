/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.server_license;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ServerLicenseTest {
    @TempDir
    Path temporaryDirectory;

    /**
     * 验证许可证使用可读 JSON 持久化，并能完整恢复业务字段。
     */
    @Test
    void shouldRoundTripJsonLicense() throws Exception {
        long now = System.currentTimeMillis();
        UUID uuid = UUID.randomUUID();
        ServerLicense.Builder builder = new ServerLicense.Builder()
                .playerName("TestPlayer")
                .startTime(now - 1_000)
                .expireTime(now + 60_000)
                .type(ServerLicense.BY_CONN)
                .allowance(3);
        builder.uuid(uuid);
        ServerLicense license = builder.end();

        license.write(temporaryDirectory.toString());

        Path licenseFile = temporaryDirectory.resolve("licenses")
                .resolve("TestPlayer." + uuid + ServerLicense.LICENSE_EXTENSION);
        String json = Files.readString(licenseFile, StandardCharsets.UTF_8);
        assertTrue(json.contains("\"formatVersion\": 1"));
        assertTrue(json.contains("\"playerName\": \"TestPlayer\""));
        assertFalse(json.contains("me.jissee.jarsauth.server_license.ServerLicense"));

        Optional<ServerLicense> restored = ServerLicense.readForPlayer(
                "TestPlayer", temporaryDirectory.toString());
        assertTrue(restored.isPresent());
        assertEquals(uuid, restored.orElseThrow().getUuid());
        assertEquals(ServerLicense.BY_CONN, restored.orElseThrow().getType());
        assertEquals(3, restored.orElseThrow().getAllowance());
    }

    /**
     * 验证历史二进制扩展名不会进入读取链路，防止重新引入原生反序列化。
     */
    @Test
    void shouldIgnoreLegacyBinaryLicense() throws Exception {
        Path folder = Files.createDirectories(temporaryDirectory.resolve("licenses"));
        Files.write(folder.resolve("TestPlayer." + UUID.randomUUID() + ".lic"),
                new byte[]{(byte) 0xAC, (byte) 0xED, 0x00, 0x05});

        Optional<ServerLicense> restored = ServerLicense.readForPlayer(
                "TestPlayer", temporaryDirectory.toString());
        assertTrue(restored.isEmpty());
    }
}
