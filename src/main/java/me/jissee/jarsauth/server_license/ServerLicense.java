/*
 * This file is part of the JarsAuth, licensed under the
 * GNU General Public License v3.0. <https://www.gnu.org/licenses/>
 *
 * Copyright (C) 2024 Jissee and contributors
 */
package me.jissee.jarsauth.server_license;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.mojang.logging.LogUtils;
import me.jissee.jarsauth.event.EventHandler;
import me.jissee.jarsauth.server_license.gui.DateParser;
import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.Reader;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Optional;
import java.util.UUID;

public class ServerLicense implements Comparable<ServerLicense> {
    private static final Logger LOGGER = LogUtils.getLogger();
    private static final Gson GSON = new GsonBuilder().setPrettyPrinting().disableHtmlEscaping().create();
    private static final int FORMAT_VERSION = 1;

    public static final int BY_MIN = 114;
    public static final int BY_CONN = 514;
    public static final int INFINITE = 114514;
    public static final String LICENSE_FOLDER = "licenses" + File.separator;
    public static final String LICENSE_EXTENSION = ".json";

    private String playerName;
    private long startTime;
    private long expireTime;
    private int type;
    private int allowance;
    private volatile boolean canBeRemoved;
    private transient UUID uuid;


    private ServerLicense(){
    }

    public String getPlayerName() {
        return playerName;
    }

    public void setPlayerName(String playerName) {
        this.playerName = playerName;
    }

    public long getStartTime() {
        return startTime;
    }

    public void setStartTime(long startTime) {
        this.startTime = startTime;
    }

    public long getExpireTime() {
        return expireTime;
    }

    public void setExpireTime(long expireTime) {
        this.expireTime = expireTime;
    }

    public int getType() {
        return type;
    }

    public void setType(int type) {
        this.type = type;
    }

    public int getAllowance() {
        return allowance;
    }

    public void setAllowance(int allowance) {
        this.allowance = allowance;
    }

    public UUID getUuid() {
        return uuid;
    }

    public boolean isInEffect(){
        long now = System.currentTimeMillis();
        return now >= startTime && now <= expireTime;
    }
    public boolean hasExpired(){
        long now = System.currentTimeMillis();
        return now > expireTime;
    }
    public boolean canBeRemoved(){
        return canBeRemoved;
    }


    /**
     * 将许可证以固定 JSON 结构原子写入，避免半写文件和 Java 原生反序列化风险。
     */
    public void write(String serverSaveDir){
        validate();
        if(uuid == null){
            throw new IllegalStateException("许可证 UUID 不能为空");
        }

        Path folder = licenseFolder(serverSaveDir);
        Path file = folder.resolve(getPlayerName() + "." + uuid + LICENSE_EXTENSION);
        Path temporary = null;
        try{
            Files.createDirectories(folder);
            temporary = Files.createTempFile(folder, ".license-", ".tmp");
            try(Writer writer = Files.newBufferedWriter(temporary, StandardCharsets.UTF_8)){
                GSON.toJson(new LicenseData(this), writer);
            }
            try{
                Files.move(temporary, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored){
                Files.move(temporary, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new RuntimeException("无法写入许可证: " + file, e);
        } finally {
            if(temporary != null){
                try{
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored){
                    // 临时文件清理由后续人工或系统完成，不覆盖原始写入异常。
                }
            }
        }
    }

    public int checkAuth(int lastType, boolean decrease){
        if(hasExpired()){
            canBeRemoved = true;
            return -1;
        }
        if(type == INFINITE && lastType == INFINITE){
            return INFINITE;
        }
        if(lastType == BY_CONN){
            return BY_CONN;
        }
        if(type == BY_CONN || type == BY_MIN){
            if(allowance == 0){
                canBeRemoved = true;
                return -1;
            }
            if(decrease){
                allowance--;
                write(EventHandler.getServerSaveDir());
            }
            return type;
        }
        canBeRemoved = true;
        return -1;
    }

    public static Optional<ServerLicense> readForPlayer(String playerName, String serverSaveDir) {
        ArrayList<ServerLicense> list = new ArrayList<>();

        File folder = licenseFolder(serverSaveDir).toFile();
        if(!folder.exists()){
            return Optional.empty();
        }
        File[] files = folder.listFiles(((dir, name) ->
                name.startsWith(playerName + ".") && name.endsWith(LICENSE_EXTENSION)));
        if(files == null){
            return Optional.empty();
        }
        for(File file : files){
            try{
                ServerLicense license = readJson(file.toPath(), playerName);
                if(license.isInEffect()){
                    license.canBeRemoved = false;
                    list.add(license);
                }
            } catch (RuntimeException e){
                LOGGER.warn("忽略无效许可证文件: {}", file, e);
            }
        }
        list.sort(ServerLicense::compareTo);
        if(list.isEmpty()){
            return Optional.empty();
        }else{
            return Optional.of(list.get(0));
        }
    }

    public static ServerLicense readFile(String fileName){
        Path folder = licenseFolder("").toAbsolutePath().normalize();
        Path file = folder.resolve(fileName).normalize();
        if(!file.getParent().equals(folder)){
            throw new IllegalArgumentException("许可证文件必须位于 licenses 目录中");
        }
        if(!Files.isRegularFile(file)){
            throw new IllegalArgumentException("许可证文件不存在: " + fileName);
        }
        return readJson(file, null);
    }

    public static void removeFile(String fileName, String serverSaveDir){
        File file = new File(serverSaveDir + LICENSE_FOLDER + fileName);
        if(file.exists()){
            file.delete();
        }
    }

    public static void removeAllInvalid(String serverSaveDir){
        File folder = licenseFolder(serverSaveDir).toFile();
        File[] files = folder.listFiles((dir, name) -> name.endsWith(LICENSE_EXTENSION));
        if(files == null){
            return;
        }
        ArrayList<String> forRemoval = new ArrayList<>();
        for(File file : files){
            try{
                ServerLicense license = readJson(file.toPath(), null);
                if(license.canBeRemoved()){
                    forRemoval.add(file.getName());
                }
            } catch (RuntimeException e){
                LOGGER.warn("忽略无效许可证文件: {}", file, e);
            }
        }
        if(!forRemoval.isEmpty()){
            for(String fname : forRemoval){
                removeFile(fname, serverSaveDir);
            }
        }
    }

    /**
     * JSON 只映射许可证所需字段，并在使用前校验文件名、版本和业务字段。
     */
    private static ServerLicense readJson(Path file, String expectedPlayerName){
        if(!file.getFileName().toString().endsWith(LICENSE_EXTENSION)){
            throw new IllegalArgumentException("不支持的许可证格式: " + file.getFileName());
        }

        LicenseData data;
        try(Reader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)){
            data = GSON.fromJson(reader, LicenseData.class);
        } catch (IOException | JsonParseException e){
            throw new IllegalArgumentException("无法读取许可证: " + file, e);
        }
        if(data == null || data.formatVersion != FORMAT_VERSION){
            throw new IllegalArgumentException("不支持的许可证版本: " + file);
        }

        ServerLicense license = data.toLicense();
        license.uuid = extractUuid(file.getFileName().toString());
        license.validate();
        String canonicalFileName = license.playerName + "." + license.uuid + LICENSE_EXTENSION;
        if(!canonicalFileName.equals(file.getFileName().toString())){
            throw new IllegalArgumentException("许可证内容与文件名不匹配: " + file);
        }
        if(expectedPlayerName != null && !expectedPlayerName.equals(license.playerName)){
            throw new IllegalArgumentException("许可证玩家名与文件名不匹配: " + file);
        }
        return license;
    }

    private static UUID extractUuid(String fileName){
        String withoutExtension = fileName.substring(0, fileName.length() - LICENSE_EXTENSION.length());
        int separator = withoutExtension.lastIndexOf('.');
        if(separator < 1 || separator == withoutExtension.length() - 1){
            throw new IllegalArgumentException("许可证文件名无效: " + fileName);
        }
        try{
            return UUID.fromString(withoutExtension.substring(separator + 1));
        } catch (IllegalArgumentException e){
            throw new IllegalArgumentException("许可证 UUID 无效: " + fileName, e);
        }
    }

    private static Path licenseFolder(String serverSaveDir){
        return Path.of(serverSaveDir, "licenses");
    }

    private void validate(){
        if(playerName == null || !playerName.matches("[A-Za-z0-9_]{1,16}")){
            throw new IllegalArgumentException("许可证玩家名无效");
        }
        if(startTime > expireTime){
            throw new IllegalArgumentException("许可证开始时间不能晚于结束时间");
        }
        if(type != BY_MIN && type != BY_CONN && type != INFINITE){
            throw new IllegalArgumentException("许可证类型无效");
        }
        if(allowance < 0){
            throw new IllegalArgumentException("许可证限额不能为负数");
        }
    }

    private static class LicenseData {
        private int formatVersion;
        private String playerName;
        private long startTime;
        private long expireTime;
        private int type;
        private int allowance;
        private boolean canBeRemoved;

        private LicenseData(){
        }

        private LicenseData(ServerLicense license){
            formatVersion = FORMAT_VERSION;
            playerName = license.playerName;
            startTime = license.startTime;
            expireTime = license.expireTime;
            type = license.type;
            allowance = license.allowance;
            canBeRemoved = license.canBeRemoved;
        }

        private ServerLicense toLicense(){
            ServerLicense license = new ServerLicense();
            license.playerName = playerName;
            license.startTime = startTime;
            license.expireTime = expireTime;
            license.type = type;
            license.allowance = allowance;
            license.canBeRemoved = canBeRemoved;
            return license;
        }
    }



    @Override
    public String toString() {
        return "ServerLicense{" +
                "playerName='" + playerName + '\'' +
                ", startTime=" + DateParser.format(startTime) +
                ", expireTime=" + DateParser.format(expireTime) +
                ", type=" + (type == BY_MIN ? "BY_MIN" : (type == BY_CONN ? "BY_CONN" : "INFINITE")) +
                ", allowance=" + allowance +
                '}';
    }

    @Override
    public int compareTo(ServerLicense o) {
        return Long.compare(this.expireTime, o.expireTime);
    }



    public static class Builder {
        private final ServerLicense license;
        public Builder(){
            license = new ServerLicense();
        }
        public Builder playerName(String playerName){
            license.setPlayerName(playerName);
            return this;
        }
        public Builder startTime(long startTime){
            license.setStartTime(startTime);
            return this;
        }
        public Builder expireTime(long expireTime){
            license.setExpireTime(expireTime);
            return this;
        }
        public Builder type(int type){
            switch (type){
                case BY_MIN:
                case BY_CONN:
                case INFINITE:
                    license.setType(type);
                    break;
                default:
                    throw new RuntimeException("Wrong type");
            }
            return this;
        }
        public Builder allowance(int allowance){
            license.setAllowance(allowance);
            return this;
        }
        public ServerLicense end(){
            return license;
        }

        public void uuid(UUID uuid) {
            license.uuid = uuid;
        }
    }


}
