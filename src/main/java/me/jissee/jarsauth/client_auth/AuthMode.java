/*
 * This file is part of JarsAuth, licensed under GPLv3.
 */
package me.jissee.jarsauth.client_auth;

/** Authentication proof carried by the Forge login handshake. */
public enum AuthMode {
    DEVICE,
    RECOVERY,
    LEGACY_MIGRATION,
    ENROLL
}
