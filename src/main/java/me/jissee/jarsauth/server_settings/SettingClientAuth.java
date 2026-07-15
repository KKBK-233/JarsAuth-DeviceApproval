/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.server_settings;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.mojang.logging.LogUtils;
import org.slf4j.Logger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class SettingClientAuth {
    private static final String FILE_NAME = "setting-client-auth.json";
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final Gson gson = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();

    private final boolean enabled;
    private final int interval;
    private final int timeout;
    private final int approvalPort;
    private final String approvalBindHost;
    private final String approvalPublicBaseUrl;
    private final int approvalPermissionLevel;
    private final int approvalExpireMinutes;

    public SettingClientAuth(
            boolean enabled,
            int interval,
            int timeout,
            int approvalPort,
            String approvalBindHost,
            String approvalPublicBaseUrl,
            int approvalPermissionLevel,
            int approvalExpireMinutes
    ){
        this.enabled = enabled;
        this.interval = interval;
        this.timeout = timeout;
        this.approvalPort = approvalPort;
        this.approvalBindHost = approvalBindHost;
        this.approvalPublicBaseUrl = approvalPublicBaseUrl;
        this.approvalPermissionLevel = approvalPermissionLevel;
        this.approvalExpireMinutes = approvalExpireMinutes;
    }
    public static SettingClientAuth load(String serverSaveDir){
        File file = new File(serverSaveDir + FILE_NAME);

        if(!file.exists()){
            try {
                LOGGER.info("Cannot find " + FILE_NAME + ", generating default setting.");
                file.createNewFile();
                SettingClientAuth setting = createDefault();

                FileWriter fw = new FileWriter(file);
                fw.write(gson.toJson(setting));
                fw.close();

                return setting;
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        try(FileReader reader = new FileReader(file)){
            int ch;
            StringBuilder sb = new StringBuilder();
            while((ch = reader.read()) != -1){
                sb.append((char)ch);
            }
            String str = sb.toString();
            SettingClientAuth loaded = gson.fromJson(str, SettingClientAuth.class);
            return loaded == null ? createDefault() : loaded.sanitize();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
    public static SettingClientAuth createDefault(){
        boolean enabled = false;
        int interval = 10;
        int timeout = 5;
        int approvalPort = 8787;
        String approvalBindHost = "0.0.0.0";
        String approvalPublicBaseUrl = "http://127.0.0.1:8787";
        int approvalPermissionLevel = 4;
        int approvalExpireMinutes = 30;

        return new SettingClientAuth(
                enabled,
                interval,
                timeout,
                approvalPort,
                approvalBindHost,
                approvalPublicBaseUrl,
                approvalPermissionLevel,
                approvalExpireMinutes
        );
    }

    private SettingClientAuth sanitize() {
        SettingClientAuth defaults = createDefault();
        return new SettingClientAuth(
                enabled,
                interval > 0 ? interval : defaults.interval,
                timeout > 0 ? timeout : defaults.timeout,
                approvalPort > 0 ? approvalPort : defaults.approvalPort,
                approvalBindHost == null || approvalBindHost.isBlank() ? defaults.approvalBindHost : approvalBindHost,
                approvalPublicBaseUrl == null || approvalPublicBaseUrl.isBlank() ? defaults.approvalPublicBaseUrl : approvalPublicBaseUrl,
                approvalPermissionLevel >= 0 ? approvalPermissionLevel : defaults.approvalPermissionLevel,
                approvalExpireMinutes > 0 ? approvalExpireMinutes : defaults.approvalExpireMinutes
        );
    }

    public boolean isEnabled(){
        return enabled;
    }
    public int getInterval(){
        return interval;
    }
    public int getTimeout(){
        return timeout;
    }
    public int getApprovalPort() {
        return approvalPort;
    }
    public String getApprovalBindHost() {
        return approvalBindHost;
    }
    public String getApprovalPublicBaseUrl() {
        return approvalPublicBaseUrl;
    }
    public int getApprovalPermissionLevel() {
        return approvalPermissionLevel;
    }
    public int getApprovalExpireMinutes() {
        return approvalExpireMinutes;
    }
}
