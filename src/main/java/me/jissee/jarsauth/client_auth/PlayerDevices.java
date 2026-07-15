/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.client_auth;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import me.jissee.jarsauth.event.EventHandler;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Optional;
import java.util.UUID;

public class PlayerDevices {
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final String FOLDER_NAME = "device-files";

    private final String playerName;
    private final ArrayList<DeviceEntry> devices;

    public PlayerDevices(String playerName, ArrayList<DeviceEntry> devices) {
        this.playerName = playerName;
        this.devices = devices;
    }

    public static PlayerDevices create(String playerName) {
        return new PlayerDevices(playerName, new ArrayList<>());
    }

    public static Optional<PlayerDevices> load(String playerName) {
        File file = resolveFile(playerName);
        if (!file.exists()) {
            return Optional.empty();
        }
        try (Reader reader = Files.newBufferedReader(file.toPath(), StandardCharsets.UTF_8)) {
            PlayerDevices loaded = GSON.fromJson(reader, PlayerDevices.class);
            if (loaded == null) {
                return Optional.empty();
            }
            return Optional.of(loaded);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void save() {
        File file = resolveFile(playerName);
        try (Writer writer = Files.newBufferedWriter(file.toPath(), StandardCharsets.UTF_8)) {
            writer.write(GSON.toJson(this));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public DeviceEntry registerNewDevice(UUID rawDeviceId, String label, boolean approved) {
        UUID hashedDeviceId = hashDeviceId(rawDeviceId);
        DeviceEntry existing = findByHashedDeviceId(hashedDeviceId).orElse(null);
        if (existing != null) {
            existing.touch();
            existing.setLabel(label);
            if (approved) {
                existing.approve();
            }
            return existing;
        }
        DeviceEntry entry = DeviceEntry.create(hashedDeviceId, label, approved);
        devices.add(entry);
        return entry;
    }

    public Optional<DeviceEntry> findByHashedDeviceId(UUID hashedDeviceId) {
        return devices.stream().filter(device -> device.hashedDeviceId.equals(hashedDeviceId)).findFirst();
    }

    public Optional<DeviceEntry> findByRequestId(String requestId) {
        return devices.stream().filter(device -> requestId.equals(device.getRequestId())).findFirst();
    }

    public int countApprovedDevices() {
        int count = 0;
        for (DeviceEntry device : devices) {
            if (device.isApproved()) {
                count++;
            }
        }
        return count;
    }

    public List<DeviceEntry> getDevices() {
        return devices;
    }

    public String getPlayerName() {
        return playerName;
    }

    public static UUID hashDeviceId(UUID rawDeviceId) {
        byte[] hashed = Codec.md5(Codec.uuidToBytes(rawDeviceId));
        return Codec.bytesToUUID(hashed);
    }

    private static File resolveFile(String playerName) {
        File folder = new File(EventHandler.getServerSaveDir() + FOLDER_NAME);
        if (!folder.exists()) {
            folder.mkdir();
        }
        return new File(folder, playerName + ".json");
    }

    public static class DeviceEntry {
        private UUID hashedDeviceId;
        private String label;
        private boolean approved;
        private long createdAt;
        private long approvedAt;
        private long lastSeenAt;
        private String requestId;

        public DeviceEntry() {
        }

        public static DeviceEntry create(UUID hashedDeviceId, String label, boolean approved) {
            long now = System.currentTimeMillis();
            DeviceEntry entry = new DeviceEntry();
            entry.hashedDeviceId = hashedDeviceId;
            entry.label = label;
            entry.approved = approved;
            entry.createdAt = now;
            entry.approvedAt = approved ? now : 0;
            entry.lastSeenAt = now;
            entry.requestId = UUID.randomUUID().toString().substring(0, 8).toLowerCase(Locale.ROOT);
            return entry;
        }

        public boolean isApproved() {
            return approved;
        }

        public void approve() {
            this.approved = true;
            this.approvedAt = System.currentTimeMillis();
            touch();
        }

        public void reject() {
            this.approved = false;
            touch();
        }

        public void touch() {
            this.lastSeenAt = System.currentTimeMillis();
        }

        public UUID getHashedDeviceId() {
            return hashedDeviceId;
        }

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public long getCreatedAt() {
            return createdAt;
        }

        public long getApprovedAt() {
            return approvedAt;
        }

        public long getLastSeenAt() {
            return lastSeenAt;
        }

        public String getRequestId() {
            return requestId;
        }
    }
}
