package com.stegobolt.engine.engine;

import com.stegobolt.engine.core.BitIO;
import com.stegobolt.engine.core.Medium;
import com.stegobolt.engine.core.MemoryHygiene;
import com.stegobolt.engine.core.Packet;
import com.stegobolt.engine.core.StegoException;
import com.stegobolt.engine.crypto.CryptoEngine;

import javax.sound.sampled.AudioFileFormat;
import javax.sound.sampled.AudioFormat;
import javax.sound.sampled.AudioInputStream;
import javax.sound.sampled.AudioSystem;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Audio Steganography (WAV, FLAC) — §4.2.
 *
 * <p><b>WAV / PCM</b> — secrets sit in the LSBs of the sample bytes themselves
 * (the noise floor, far below human hearing) via {@code javax.sound.sampled}.
 * One bit per sample byte: 16-bit PCM ⇒ 2 embeddable bits per frame.
 *
 * <p><b>FLAC</b> — secrets are carried in a hidden structural PADDING metadata
 * block (the phase/padding layer of the stream) so the audio frames stay
 * bit-identical and any player renders the sound untouched.
 */
public final class AudioStegoEngine implements StegoEngine {

    private static final int FLAC_HEADER = 4;

    @Override
    public Medium medium() {
        return Medium.AUDIO;
    }

    @Override
    public long capacityBits(byte[] cover) {
        if (isFlac(cover)) {
            return flacCapacityBits(cover);
        }
        return readPcm(cover).length; // one embeddable bit per sample byte
    }

    @Override
    public byte[] hide(byte[] cover, byte[] container) {
        return isFlac(cover) ? hideFlac(cover, container) : hidePcm(cover, container);
    }

    @Override
    public byte[] extract(byte[] cover) {
        return isFlac(cover) ? extractFlac(cover) : extractPcm(cover);
    }

    @Override
    public SanitizeOutcome sanitize(byte[] cover, boolean randomizeLsb) {
        if (isFlac(cover)) {
            byte[] embedded = extractFlac(cover);
            long gone = embedded == null ? 0 : embedded.length * 8L;
            if (embedded != null) {
                MemoryHygiene.wipe(embedded);
            }
            byte[] cleaned = hideFlac(cover, new byte[0]); // empty padding payload
            return new SanitizeOutcome(cleaned, gone, gone);
        }
        AudioTrack track = decodeTrack(cover);
        byte[] samples = track.samples();
        long changed = 0;
        long randomized = 0;
        if (randomizeLsb) {
            java.security.SecureRandom rng = CryptoEngine.newRng();
            byte[] original = samples.clone();
            for (int i = 0; i < samples.length; i++) {
                samples[i] = (byte) ((samples[i] & 0xFE) | rng.nextInt(2));
            }
            changed = BitIO.changedBits(original, samples);
            randomized = samples.length;
            MemoryHygiene.wipe(original);
        }
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (AudioInputStream outAis = new AudioInputStream(
                    new ByteArrayInputStream(samples), track.format(), track.frames())) {
                AudioSystem.write(outAis, AudioFileFormat.Type.WAVE, out);
            }
            return new SanitizeOutcome(out.toByteArray(), changed, randomized);
        } catch (IOException e) {
            throw new StegoException("Sanitized audio encoding failed", e);
        } finally {
            MemoryHygiene.wipe(samples);
        }
    }

    /* ------------------------------------------------------------------ */
    /* WAV / PCM — sample noise-floor LSB                                  */
    /* ------------------------------------------------------------------ */

    private static byte[] readPcm(byte[] cover) {
        try (AudioInputStream ais = AudioSystem.getAudioInputStream(new ByteArrayInputStream(cover))) {
            AudioFormat format = ais.getFormat();
            if (format.getSampleSizeInBits() % 8 != 0 || format.getSampleSizeInBits() <= 0) {
                throw new StegoException("Only byte-aligned PCM audio is supported (WAV / AIFF)");
            }
            return ais.readAllBytes();
        } catch (IOException | RuntimeException e) {
            if (e instanceof StegoException se) {
                throw se;
            }
            throw new StegoException("Audio could not be decoded — expected WAV/PCM (or FLAC)", e);
        }
    }

    private static AudioTrack decodeTrack(byte[] cover) {
        try (AudioInputStream ais = AudioSystem.getAudioInputStream(new ByteArrayInputStream(cover))) {
            byte[] samples = ais.readAllBytes();
            return new AudioTrack(ais.getFormat(), samples, samples.length / Math.max(1, ais.getFormat().getFrameSize()));
        } catch (IOException | RuntimeException e) {
            throw new StegoException("Audio could not be decoded — expected WAV/PCM (or FLAC)", e);
        }
    }

    private record AudioTrack(AudioFormat format, byte[] samples, long frames) {
    }

    private static byte[] hidePcm(byte[] cover, byte[] container) {
        AudioTrack track = decodeTrack(cover);
        byte[] samples = track.samples();
        long capacityBits = samples.length; // one bit per sample byte
        long needed = container.length * 8L;
        if (needed > capacityBits) {
            throw new StegoException("Payload too large for this audio — capacity is "
                    + (capacityBits / 8) + " bytes, payload needs " + container.length + " bytes");
        }
        try {
            BitIO.write(container, 0, (index, bit) -> {
                int i = (int) index;
                samples[i] = (byte) ((samples[i] & 0xFE) | bit);
            });
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try (AudioInputStream outAis = new AudioInputStream(
                    new ByteArrayInputStream(samples), track.format(), track.frames())) {
                AudioSystem.write(outAis, AudioFileFormat.Type.WAVE, out);
            }
            return out.toByteArray();
        } catch (IOException e) {
            throw new StegoException("Stego audio encoding failed", e);
        } finally {
            MemoryHygiene.wipe(samples);
        }
    }

    private static byte[] extractPcm(byte[] cover) {
        byte[] samples = readPcm(cover);
        try {
            // One bit per sample byte: the 40-byte header needs 320 sample bytes.
            if (samples.length < Packet.HEADER * 8L) {
                return null;
            }
            byte[] header = BitIO.read(Packet.HEADER * 8L, 0, i -> samples[(int) i] & 1);
            if (!Packet.looksLikeHeader(header)) {
                return null;
            }
            int ctLen = BitIO.getInt(header, 8);
            long total = (long) Packet.HEADER + ctLen;
            if (total * 8L > samples.length) {
                return null;
            }
            byte[] raw = BitIO.read(total * 8L, 0, i -> samples[(int) i] & 1);
            return Packet.looksLike(raw) ? raw : null;
        } finally {
            MemoryHygiene.wipe(samples);
        }
    }

    /* ------------------------------------------------------------------ */
    /* FLAC — hidden PADDING metadata block                                */
    /* ------------------------------------------------------------------ */

    private static boolean isFlac(byte[] cover) {
        return cover.length > FLAC_HEADER
                && cover[0] == 'f' && cover[1] == 'L' && cover[2] == 'a' && cover[3] == 'C';
    }

    /**
     * The embeddable sample stream for steganalysis: raw PCM sample bytes for
     * WAV, the file bytes for FLAC (padding-layer medium). Caller wipes the result.
     */
    public static byte[] sampleStream(byte[] cover) {
        return isFlac(cover) ? cover.clone() : readPcm(cover);
    }

    /**
     * FLAC layout: "fLaC" then metadata blocks (1 flag/type byte + 3-byte length),
     * the last one flagged 0x80. We rebuild the metadata section with a PADDING
     * block (type 0) appended last that carries the SBV2-J container after a
     * 4-byte "SB2J" guard; audio frames are copied through untouched.
     */
    private static byte[] hideFlac(byte[] cover, byte[] container) {
        // ---- 1. parse existing metadata blocks -----------------------------
        java.util.ArrayList<int[]> meta = new java.util.ArrayList<>(); // {type, start, end}
        int pos = FLAC_HEADER;
        int audioStart = -1;
        while (pos + 4 <= cover.length) {
            int head = cover[pos] & 0xFF;
            boolean last = (head & 0x80) != 0;
            int type = head & 0x7F;
            int len = ((cover[pos + 1] & 0xFF) << 16) | ((cover[pos + 2] & 0xFF) << 8) | (cover[pos + 3] & 0xFF);
            int blockEnd = pos + 4 + len;
            if (blockEnd > cover.length) {
                throw new StegoException("Corrupt FLAC metadata block");
            }
            if (type != 0) {
                meta.add(new int[]{type, pos + 4, blockEnd});
            }
            pos = blockEnd;
            if (last) {
                audioStart = blockEnd;
                break;
            }
        }
        if (audioStart < 0) {
            throw new StegoException("FLAC metadata blocks not found");
        }

        byte[] payload = new byte[Packet.MAGIC.length + container.length];
        System.arraycopy(Packet.MAGIC, 0, payload, 0, Packet.MAGIC.length);
        System.arraycopy(container, 0, payload, Packet.MAGIC.length, container.length);

        // ---- 2. rebuild metadata + copy audio frames -----------------------
        ByteArrayOutputStream out = new ByteArrayOutputStream(cover.length + payload.length + 8);
        out.write(cover, 0, FLAC_HEADER);
        for (int[] block : meta) {
            out.write(block[0] & 0x7F); // last-flag cleared — our padding is last
            int len = block[2] - block[1];
            out.write((len >>> 16) & 0xFF);
            out.write((len >>> 8) & 0xFF);
            out.write(len & 0xFF);
            out.write(cover, block[1], len);
        }
        out.write(0x80); // PADDING, last metadata block
        int newLen = payload.length;
        out.write((newLen >>> 16) & 0xFF);
        out.write((newLen >>> 8) & 0xFF);
        out.write(newLen & 0xFF);
        out.write(payload);
        out.write(cover, audioStart, cover.length - audioStart);
        return out.toByteArray();
    }

    private static byte[] extractFlac(byte[] cover) {
        int pos = FLAC_HEADER;
        while (pos + 4 <= cover.length) {
            int head = cover[pos] & 0xFF;
            boolean last = (head & 0x80) != 0;
            int type = head & 0x7F;
            int len = ((cover[pos + 1] & 0xFF) << 16) | ((cover[pos + 2] & 0xFF) << 8) | (cover[pos + 3] & 0xFF);
            int blockEnd = pos + 4 + len;
            if (blockEnd > cover.length) {
                return null;
            }
            if (type == 0 && len > Packet.MAGIC.length) {
                boolean match = true;
                for (int i = 0; i < Packet.MAGIC.length; i++) {
                    if (cover[pos + 4 + i] != Packet.MAGIC[i]) {
                        match = false;
                        break;
                    }
                }
                if (match) {
                    return Arrays.copyOfRange(cover, pos + 4 + Packet.MAGIC.length, blockEnd);
                }
            }
            if (last) {
                break;
            }
            pos = blockEnd;
        }
        return null;
    }

    private static long flacCapacityBits(byte[] cover) {
        // A PADDING block can carry a large hidden stream; bound it to 256 KiB.
        return 256L * 1024L * 8L;
    }
}
