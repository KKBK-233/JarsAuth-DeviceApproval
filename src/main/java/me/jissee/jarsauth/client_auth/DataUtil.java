/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.client_auth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.jissee.jarsauth.Compatibility;
import net.minecraftforge.api.distmarker.Dist;
import net.minecraftforge.api.distmarker.OnlyIn;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Optional;
import java.util.UUID;

public class DataUtil {
    private static final String DEVICE_FOLDER = "device-files";
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    @OnlyIn(Dist.CLIENT)
    public static void saveDeviceIdentity(String serverID, String playerName, DeviceIdentity identity) {
        File folder = getFolder();
        File file = new File(folder, buildFileName(serverID, playerName));
        try (Writer writer = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
            writer.write(GSON.toJson(identity));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @OnlyIn(Dist.CLIENT)
    public static Optional<DeviceIdentity> readDeviceIdentity(String serverID, String playerName) {
        File folder = getFolder();
        File file = new File(folder, buildFileName(serverID, playerName));
        if (!file.exists()) {
            return Optional.empty();
        }
        try (Reader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            DeviceIdentity identity = GSON.fromJson(reader, DeviceIdentity.class);
            return Optional.ofNullable(identity);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @OnlyIn(Dist.CLIENT)
    public static DeviceIdentity createAndSaveIdentity(String serverID, String playerName, UUID deviceId) {
        DeviceIdentity identity = DeviceIdentity.create(deviceId, playerName);
        saveDeviceIdentity(serverID, playerName, identity);
        return identity;
    }

    @OnlyIn(Dist.CLIENT)
    public static String suggestDeviceLabel(String playerName) {
        return DeviceIdentity.defaultLabel(playerName);
    }

    private static File getFolder() {
        String clientDir = Compatibility.getClientRootDir();
        File folder = new File(clientDir + DEVICE_FOLDER);
        if (!folder.exists()) {
            folder.mkdir();
        }
        return folder;
    }

    private static String buildFileName(String serverID, String playerName) {
        byte[] hashed = Codec.md5(serverID.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte hashByte : hashed) {
            sb.append(String.format("%02x", hashByte));
        }
        return sb + "." + playerName + ".json";
    }
}
