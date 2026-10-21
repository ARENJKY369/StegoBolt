package com.stegobolt.engine.core;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Content sniffing — decides which of the six mediums a carrier belongs to
 * using magic bytes first, filename extension as fallback.
 */
public final class Sniffer {

    private Sniffer() {
    }

    public static Medium sniff(byte[] data, String filename) {
        if (data == null || data.length < 4) {
            throw new StegoException("Carrier is empty or too small");
        }
        String name = filename == null ? "" : filename.toLowerCase(Locale.ROOT);

        // ---- Images -------------------------------------------------------
        if (startsWith(data, (byte) 0x89, (byte) 'P', (byte) 'N', (byte) 'G')) {
            return Medium.IMAGE;
        }
        if (startsWith(data, (byte) 'B', (byte) 'M')) {
            return Medium.IMAGE;
        }
        if (startsWith(data, (byte) 'G', (byte) 'I', (byte) 'F', (byte) '8')) {
            return Medium.IMAGE;
        }
        if (startsWith(data, (byte) 'I', (byte) 'I', (byte) 0x2A, (byte) 0x00)
                || startsWith(data, (byte) 'M', (byte) 'M', (byte) 0x00, (byte) 0x2A)) {
            return Medium.IMAGE;
        }
        if (startsWith(data, (byte) 0xFF, (byte) 0xD8, (byte) 0xFF)) {
            return Medium.IMAGE;
        }
        if (startsWith(data, (byte) 'R', (byte) 'I', (byte) 'F', (byte) 'F') && asciiAt(data, 8, 4).equals("WEBP")) {
            return Medium.IMAGE;
        }

        // ---- Audio --------------------------------------------------------
        if (startsWith(data, (byte) 'R', (byte) 'I', (byte) 'F', (byte) 'F') && asciiAt(data, 8, 4).equals("WAVE")) {
            return Medium.AUDIO;
        }
        if (startsWith(data, (byte) 'f', (byte) 'L', (byte) 'a', (byte) 'C')) {
            return Medium.AUDIO;
        }

        // ---- Video --------------------------------------------------------
        if (startsWith(data, (byte) 'R', (byte) 'I', (byte) 'F', (byte) 'F') && asciiAt(data, 8, 4).equals("AVI ")) {
            return Medium.VIDEO;
        }
        if (asciiAt(data, 4, 4).equals("ftyp")) {
            return Medium.VIDEO;
        }
        if (startsWith(data, (byte) 0x1A, (byte) 0x45, (byte) 0xDF, (byte) 0xA3)) {
            return Medium.VIDEO;
        }

        // ---- Documents ----------------------------------------------------
        if (startsWith(data, (byte) '%', (byte) 'P', (byte) 'D', (byte) 'F')) {
            return Medium.DOCUMENT;
        }
        if (startsWith(data, (byte) 'P', (byte) 'K', (byte) 0x03, (byte) 0x04)) {
            return Medium.DOCUMENT; // OPC/ZIP family (DOCX)
        }

        // ---- Network ------------------------------------------------------
        if (isPcap(data)) {
            return Medium.NETWORK;
        }

        // ---- Text / source code -------------------------------------------
        if (name.endsWith(".txt") || name.endsWith(".java") || name.endsWith(".js")
                || name.endsWith(".ts") || name.endsWith(".c") || name.endsWith(".cpp")
                || name.endsWith(".h") || name.endsWith(".hpp") || name.endsWith(".py")
                || name.endsWith(".md") || name.endsWith(".csv") || name.endsWith(".json")) {
            return Medium.TEXT;
        }
        if (looksLikeText(data)) {
            return Medium.TEXT;
        }
        throw new StegoException("Unsupported carrier format — expected image, audio, video, document, text/code or PCAP traffic");
    }

    public static boolean isPcap(byte[] data) {
        if (data.length < 24) {
            return false;
        }
        // Classic libpcap magic (both endiannesses, µs and ns resolutions) + pcapng.
        return startsWith(data, (byte) 0xA1, (byte) 0xB2, (byte) 0xC3, (byte) 0xD4)
                || startsWith(data, (byte) 0xD4, (byte) 0xC3, (byte) 0xB2, (byte) 0xA1)
                || startsWith(data, (byte) 0xA1, (byte) 0xB2, (byte) 0x3C, (byte) 0x4D)
                || startsWith(data, (byte) 0x4D, (byte) 0x3C, (byte) 0xB2, (byte) 0xA1)
                || startsWith(data, (byte) 0x0A, (byte) 0x0D, (byte) 0x0D, (byte) 0x0A);
    }

    private static boolean looksLikeText(byte[] data) {
        int sample = Math.min(data.length, 512);
        int control = 0;
        for (int i = 0; i < sample; i++) {
            int b = data[i] & 0xFF;
            if (b == 0) {
                return false;
            }
            if (b < 0x09 || (b > 0x0D && b < 0x20)) {
                control++;
            }
        }
        return control * 20 < sample; // < 5% control bytes → treat as text
    }

    private static boolean startsWith(byte[] data, byte... prefix) {
        if (data.length < prefix.length) {
            return false;
        }
        for (int i = 0; i < prefix.length; i++) {
            if (data[i] != prefix[i]) {
                return false;
            }
        }
        return true;
    }

    private static String asciiAt(byte[] data, int offset, int len) {
        if (data.length < offset + len) {
            return "";
        }
        return new String(data, offset, len, StandardCharsets.US_ASCII);
    }
}
