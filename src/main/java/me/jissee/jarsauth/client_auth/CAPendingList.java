/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.client_auth;

import com.mojang.logging.LogUtils;
import me.jissee.jarsauth.Compatibility;
import me.jissee.jarsauth.server_settings.SettingClientAuth;
import me.jissee.jarsauth.server_settings.Settings;
import net.minecraft.ChatFormatting;
import net.minecraft.network.chat.ClickEvent;
import net.minecraft.network.chat.Component;
import net.minecraft.network.chat.HoverEvent;
import net.minecraft.network.chat.MutableComponent;
import net.minecraft.server.level.ServerPlayer;
import org.slf4j.Logger;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

public class CAPendingList {
    private static final Logger LOGGER = LogUtils.getLogger();

    private static final CAPendingList instance = new CAPendingList();

    public static CAPendingList getInstance() {
        return instance;
    }

    private final HashMap<String, PendingApproval> approvalsByToken = new HashMap<>();
    private final HashMap<String, PendingApproval> approvalsByRequestId = new HashMap<>();

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

}
