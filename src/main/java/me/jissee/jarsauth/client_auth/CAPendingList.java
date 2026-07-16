/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.client_auth;

import com.mojang.logging.LogUtils;
import me.jissee.jarsauth.Compatibility;
import me.jissee.jarsauth.event.EventHandler;
import me.jissee.jarsauth.packet.CABroadcastPacket;
import me.jissee.jarsauth.server_license.SLPendingList;
import me.jissee.jarsauth.server_settings.SettingClientAuth;
import me.jissee.jarsauth.server_settings.Settings;
import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.ClickEvent;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.HoverEvent;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.server.level.ServerPlayer;
import org.slf4j.Logger;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

public class CAPendingList {
    private static final Logger LOGGER = LogUtils.getLogger();

    private static final CAPendingList instance = new CAPendingList();

    public static CAPendingList getInstance() {
        return instance;
    }

    private final HashMap<String, AuthSession> waiting = new HashMap<>();
    private final HashMap<String, Long> loggedIn = new HashMap<>();
    private final ArrayList<ServerPlayer> newPlayers = new ArrayList<>();
    private final HashMap<String, PendingApproval> approvalsByToken = new HashMap<>();
    private final HashMap<String, PendingApproval> approvalsByRequestId = new HashMap<>();

    public void playerLogin(ServerPlayer player) {
        String playerName = player.getName().getString();
        Optional<PlayerDevices> devices = PlayerDevices.load(playerName);

        if (devices.isEmpty()) {
            synchronized (newPlayers) {
                newPlayers.add(player);
            }
            if (!Settings.getFileChecksumSetting().isEnabled()) {
                allowNew(player);
            }
            return;
        }

        startChallenge(player);
    }

    public void allowNew(ServerPlayer player) {
        boolean isNew;
        synchronized (newPlayers) {
            isNew = newPlayers.remove(player);
        }
        if (!isNew || Compatibility.hasDisconnected(player)) {
            return;
        }

        AuthSession session = AuthSession.expectRegistration();
        session.setLoginTime(System.currentTimeMillis());
        synchronized (waiting) {
            waiting.put(player.getName().getString(), session);
        }
        Compatibility.sendModPacket(player, new CABroadcastPacket(Settings.getServerID().getServerID(), CABroadcastPacket.AUTH_INFO, new byte[]{}));
    }

    public void handleRegisterRequest(String serverID, ServerPlayer player, DeviceRegistrationRequest request) {
        synchronized (waiting) {
            if (!Settings.getServerID().getServerID().equals(serverID)) {
                return;
            }
            String playerName = player.getName().getString();
            AuthSession session = waiting.get(playerName);
            if (session == null) {
                return;
            }

            PlayerDevices devices = PlayerDevices.load(playerName).orElse(PlayerDevices.create(playerName));
            UUID rawDeviceId = UUID.randomUUID();
            boolean approved = devices.countApprovedDevices() == 0;
            PlayerDevices.DeviceEntry deviceEntry = devices.registerNewDevice(rawDeviceId, sanitizeLabel(request.getDeviceLabel(), playerName), approved);
            devices.save();

            try {
                PublicKey publicKey = Codec.byteArr2PublicKey(request.getPublicKey());
                byte[] cipher = Codec.encrypt(Codec.uuidToBytes(rawDeviceId), publicKey);
                Compatibility.sendModPacket(player, new CABroadcastPacket(Settings.getServerID().getServerID(), CABroadcastPacket.AUTH_INFO, cipher));
            } catch (Exception e) {
                throw new RuntimeException(e);
            } finally {
                waiting.remove(playerName);
            }

            if (approved) {
                LOGGER.info("Auto approved first device [{}] for player {}", deviceEntry.getRequestId(), playerName);
                EventHandler.addPlayerToBeRemove(player, Compatibility.translatable("text.firsttime"), 10);
                return;
            }

            PendingApproval approval = createOrRefreshApproval(playerName, deviceEntry);
            LOGGER.info("Device [{}] for player {} is waiting for approval", approval.requestId, playerName);
            notifyAdmins(approval);
            EventHandler.addPlayerToBeRemove(player, Compatibility.translatable("text.caauth.pending"), 10);
        }
    }

    public void addAuthInfo(String serverID, ServerPlayer player, byte[] payload) {
        synchronized (waiting) {
            if (!Settings.getServerID().getServerID().equals(serverID)) {
                return;
            }

            String playerName = player.getName().getString();
            AuthSession session = waiting.get(playerName);
            if (session == null || session.getPrivateKey() == null) {
                return;
            }

            try {
                byte[] uuidDec = Codec.decrypt(payload, session.getPrivateKey());
                UUID rawDeviceId = Codec.bytesToUUID(uuidDec);
                UUID hashedDeviceId = PlayerDevices.hashDeviceId(rawDeviceId);

                PlayerDevices devices = PlayerDevices.load(playerName).orElse(null);
                if (devices == null) {
                    EventHandler.addPlayerToBeRemove(player, Compatibility.translatable("text.caauth.fail"), 0);
                    waiting.remove(playerName);
                    return;
                }

                Optional<PlayerDevices.DeviceEntry> deviceEntry = devices.findByHashedDeviceId(hashedDeviceId);
                if (deviceEntry.isEmpty()) {
                    EventHandler.addPlayerToBeRemove(player, Compatibility.translatable("text.caauth.fail"), 0);
                    waiting.remove(playerName);
                    return;
                }

                PlayerDevices.DeviceEntry entry = deviceEntry.get();
                entry.touch();
                devices.save();
                waiting.remove(playerName);

                if (entry.isApproved()) {
                    synchronized (loggedIn) {
                        loggedIn.put(playerName, System.currentTimeMillis());
                    }
                    LOGGER.debug("Player {} passed CA authentication", playerName);
                    SLPendingList.getInstance().allowNew(player);
                    return;
                }

                PendingApproval approval = createOrRefreshApproval(playerName, entry);
                LOGGER.info("Pending device [{}] for player {} retried login", approval.requestId, playerName);
                notifyAdmins(approval);
                EventHandler.addPlayerToBeRemove(player, Compatibility.translatable("text.caauth.pending"), 0);
            } catch (Exception ignored) {
            }
        }
    }

    public boolean approvePendingByToken(String token) {
        PendingApproval approval;
        synchronized (approvalsByToken) {
            approval = approvalsByToken.get(token);
        }
        return approval != null && approvePendingByRequestId(approval.requestId);
    }

    public boolean rejectPendingByToken(String token) {
        PendingApproval approval;
        synchronized (approvalsByToken) {
            approval = approvalsByToken.get(token);
        }
        return approval != null && rejectPendingByRequestId(approval.requestId);
    }

    public boolean approvePendingByRequestId(String requestId) {
        PendingApproval approval;
        synchronized (approvalsByToken) {
            approval = approvalsByRequestId.get(requestId);
            if (approval == null || approval.isExpired()) {
                removeApprovalInternal(approval);
                return false;
            }
        }

        String label;
        synchronized (PlayerDevices.accountLock(approval.playerName)) {
            PlayerDevices devices = PlayerDevices.load(approval.playerName).orElse(null);
            if (devices == null) {
                synchronized (approvalsByToken) {
                    removeApprovalInternal(approval);
                }
                return false;
            }

            Optional<PlayerDevices.DeviceEntry> deviceEntry = devices.findByRequestId(requestId);
            if (deviceEntry.isEmpty()) {
                synchronized (approvalsByToken) {
                    removeApprovalInternal(approval);
                }
                return false;
            }

            PlayerDevices.DeviceEntry entry = deviceEntry.get();
            if (!devices.isV2() && entry.getCandidateRecoveryPublicKey() != null) {
                devices.enableV2(entry.getCandidateRecoveryPublicKey());
            }
            entry.approve();
            label = entry.getLabel();
            devices.save();
        }
        synchronized (approvalsByToken) {
            if (approvalsByRequestId.get(requestId) == approval) {
                removeApprovalInternal(approval);
            }
        }
        broadcastAdminResult(Component.translatable("text.caauth.approved", approval.playerName, label, requestId));
        return true;
    }

    public boolean rejectPendingByRequestId(String requestId) {
        PendingApproval approval;
        synchronized (approvalsByToken) {
            approval = approvalsByRequestId.get(requestId);
            if (approval == null || approval.isExpired()) {
                removeApprovalInternal(approval);
                return false;
            }
        }
        synchronized (PlayerDevices.accountLock(approval.playerName)) {
            PlayerDevices devices = PlayerDevices.load(approval.playerName).orElse(null);
            if (devices != null) {
                devices.findByRequestId(requestId).ifPresent(devices::removeDevice);
                devices.save();
            }
        }
        synchronized (approvalsByToken) {
            removeApprovalInternal(approval);
        }
        broadcastAdminResult(Component.translatable("text.caauth.rejected", approval.playerName, approval.deviceLabel, requestId));
        return true;
    }

    public List<PendingApproval> listPendingApprovals() {
        synchronized (approvalsByToken) {
            ArrayList<PendingApproval> result = new ArrayList<>();
            for (PendingApproval approval : approvalsByToken.values()) {
                if (!approval.isExpired()) {
                    result.add(approval);
                }
            }
            result.sort((left, right) -> Long.compare(left.createdAt, right.createdAt));
            return result;
        }
    }

    /** Creates one persistent-device approval capability without requiring a ServerPlayer. */
    public PendingApproval ensurePendingApproval(PlayerDevices devices, PlayerDevices.DeviceEntry entry) {
        synchronized (approvalsByToken) {
            PendingApproval existing = approvalsByRequestId.get(entry.getRequestId());
            if (existing != null && !existing.isExpired()) {
                return existing;
            }
            PendingApproval approval = createOrRefreshApproval(devices.getPlayerName(), entry);
            LOGGER.info("Device [{}] for player {} is waiting for approval", approval.requestId, devices.getPlayerName());
            notifyAdmins(approval);
            return approval;
        }
    }

    /** Restores command/HTTP approval handles after a server restart. */
    public void restorePersistentApprovals() {
        for (PlayerDevices devices : PlayerDevices.loadAll()) {
            for (PlayerDevices.DeviceEntry entry : devices.getDevices()) {
                if (entry.isPending()) {
                    ensurePendingApproval(devices, entry);
                }
            }
        }
    }

    public void notifyPendingApprovals(ServerPlayer admin) {
        int permissionLevel = Settings.getClientAuthSetting().getApprovalPermissionLevel();
        if (!admin.hasPermissions(permissionLevel)) {
            return;
        }
        for (PendingApproval approval : listPendingApprovals()) {
            Compatibility.sendSystemMessage(admin, buildApprovalMessage(approval));
        }
    }

    public void tick() {
        long millTime = System.currentTimeMillis();

        synchronized (waiting) {
            Iterator<Map.Entry<String, AuthSession>> iterator = waiting.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, AuthSession> entry = iterator.next();
                ServerPlayer player = Compatibility.getPlayerByName(entry.getKey());
                if (Compatibility.hasDisconnected(player)) {
                    iterator.remove();
                    continue;
                }

                long timeout = Settings.getClientAuthSetting().getTimeout();
                if (millTime - entry.getValue().getLoginTime() > timeout * 1000L) {
                    EventHandler.addPlayerToBeRemove(player, Compatibility.translatable("text.caauth.timeout"), 0);
                    iterator.remove();
                }
            }
        }

        synchronized (loggedIn) {
            Iterator<Map.Entry<String, Long>> iterator = loggedIn.entrySet().iterator();
            while (iterator.hasNext()) {
                Map.Entry<String, Long> entry = iterator.next();
                ServerPlayer player = Compatibility.getPlayerByName(entry.getKey());
                if (Compatibility.hasDisconnected(player)) {
                    iterator.remove();
                    continue;
                }

                long interval = Settings.getClientAuthSetting().getInterval();
                if (interval > 0 && millTime - entry.getValue() > interval * 1000L) {
                    iterator.remove();
                    startChallenge(player);
                }
            }
        }

        synchronized (newPlayers) {
            newPlayers.removeIf(Compatibility::hasDisconnected);
        }

        synchronized (approvalsByToken) {
            Iterator<PendingApproval> iterator = approvalsByToken.values().iterator();
            while (iterator.hasNext()) {
                PendingApproval approval = iterator.next();
                if (approval.isExpired()) {
                    approvalsByRequestId.remove(approval.requestId);
                    iterator.remove();
                }
            }
        }
    }

    private void startChallenge(ServerPlayer player) {
        try {
            KeyPair pair = Codec.generateKeyPair();
            AuthSession session = AuthSession.expectExisting(pair.getPrivate());
            session.setLoginTime(System.currentTimeMillis());
            synchronized (waiting) {
                waiting.put(player.getName().getString(), session);
            }
            Compatibility.sendModPacket(player, new CABroadcastPacket(Settings.getServerID().getServerID(), CABroadcastPacket.PUBLIC_KEY, pair.getPublic().getEncoded()));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private PendingApproval createOrRefreshApproval(String playerName, PlayerDevices.DeviceEntry entry) {
        SettingClientAuth setting = Settings.getClientAuthSetting();
        PendingApproval old = approvalsByRequestId.remove(entry.getRequestId());
        if (old != null) {
            approvalsByToken.remove(old.token);
        }
        PendingApproval approval = new PendingApproval(
                entry.getRequestId(),
                UUID.randomUUID().toString().replace("-", ""),
                playerName,
                entry.getLabel(),
                System.currentTimeMillis(),
                System.currentTimeMillis() + setting.getApprovalExpireMinutes() * 60_000L
        );
        approvalsByToken.put(approval.token, approval);
        approvalsByRequestId.put(approval.requestId, approval);
        return approval;
    }

    private void notifyAdmins(PendingApproval approval) {
        boolean sent = false;
        int permissionLevel = Settings.getClientAuthSetting().getApprovalPermissionLevel();
        for (ServerPlayer onlinePlayer : Compatibility.getOnlinePlayers()) {
            if (onlinePlayer.hasPermissions(permissionLevel)) {
                Compatibility.sendSystemMessage(onlinePlayer, buildApprovalMessage(approval));
                sent = true;
            }
        }
        if (!sent) {
            LOGGER.info("No online admin available for pending device [{}] of player {}", approval.requestId, approval.playerName);
        }
    }

    private MutableComponent buildApprovalMessage(PendingApproval approval) {
        MutableComponent head = Component.literal("[JarsAuth] ")
                .withStyle(ChatFormatting.GOLD)
                .append(Component.translatable("text.caauth.pending.detail", approval.playerName, approval.deviceLabel, approval.requestId).withStyle(ChatFormatting.YELLOW))
                .append(Component.literal(" "));

        MutableComponent approve = Component.translatable("text.caauth.approve.link")
                        .withStyle(style -> style
                        .withColor(ChatFormatting.GREEN)
                        .withUnderlined(true)
                        .withHoverEvent(new HoverEvent(HoverEvent.Action.SHOW_TEXT, Component.literal(approval.getApproveUrl())))
                        .withClickEvent(new ClickEvent(ClickEvent.Action.OPEN_URL, approval.getApproveUrl())));

        MutableComponent reject = Component.translatable("text.caauth.reject.link")
                        .withStyle(style -> style
                        .withColor(ChatFormatting.RED)
                        .withUnderlined(true)
                        .withHoverEvent(new HoverEvent(HoverEvent.Action.SHOW_TEXT, Component.literal(approval.getRejectUrl())))
                        .withClickEvent(new ClickEvent(ClickEvent.Action.OPEN_URL, approval.getRejectUrl())));

        return head.append(approve).append(Component.literal(" ")).append(reject);
    }

    private void broadcastAdminResult(Component msg) {
        int permissionLevel = Settings.getClientAuthSetting().getApprovalPermissionLevel();
        for (ServerPlayer onlinePlayer : Compatibility.getOnlinePlayers()) {
            if (onlinePlayer.hasPermissions(permissionLevel)) {
                Compatibility.sendSystemMessage(onlinePlayer, msg);
            }
        }
        LOGGER.info(msg.getString());
    }

    private void removeApprovalInternal(PendingApproval approval) {
        if (approval == null) {
            return;
        }
        approvalsByToken.remove(approval.token);
        approvalsByRequestId.remove(approval.requestId);
    }

    private String sanitizeLabel(String deviceLabel, String playerName) {
        if (deviceLabel == null || deviceLabel.isBlank()) {
            return DeviceIdentity.defaultLabel(playerName);
        }
        String normalized = deviceLabel.replaceAll("[\\r\\n\\t]", " ").trim();
        if (normalized.length() > 48) {
            return normalized.substring(0, 48);
        }
        return normalized;
    }

    public static class PendingApproval {
        private final String requestId;
        private final String token;
        private final String playerName;
        private final String deviceLabel;
        private final long createdAt;
        private final long expireAt;

        private PendingApproval(String requestId, String token, String playerName, String deviceLabel, long createdAt, long expireAt) {
            this.requestId = requestId;
            this.token = token;
            this.playerName = playerName;
            this.deviceLabel = deviceLabel;
            this.createdAt = createdAt;
            this.expireAt = expireAt;
        }

        public boolean isExpired() {
            return System.currentTimeMillis() > expireAt;
        }

        public String getApproveUrl() {
            return buildUrl("/approve");
        }

        public String getRejectUrl() {
            return buildUrl("/reject");
        }

        public String getRequestId() {
            return requestId;
        }

        public String getPlayerName() {
            return playerName;
        }

        public String getDeviceLabel() {
            return deviceLabel;
        }

        private String buildUrl(String path) {
            String base = Settings.getClientAuthSetting().getApprovalPublicBaseUrl();
            if (base.endsWith("/")) {
                base = base.substring(0, base.length() - 1);
            }
            return base + path + "?token=" + token;
        }
    }

    private static class AuthSession {
        private final SessionType type;
        private final PrivateKey privateKey;
        private long loginTime;

        private AuthSession(SessionType type, PrivateKey privateKey) {
            this.type = type;
            this.privateKey = privateKey;
        }

        public static AuthSession expectRegistration() {
            return new AuthSession(SessionType.REGISTRATION, null);
        }

        public static AuthSession expectExisting(PrivateKey privateKey) {
            return new AuthSession(SessionType.EXISTING_AUTH, privateKey);
        }

        public PrivateKey getPrivateKey() {
            return privateKey;
        }

        public long getLoginTime() {
            return loginTime;
        }

        public void setLoginTime(long loginTime) {
            this.loginTime = loginTime;
        }
    }

    private enum SessionType {
        REGISTRATION,
        EXISTING_AUTH
    }
}
