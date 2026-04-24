package com.bonyx.player; // Make sure this package name matches your project structure!

import android.net.Uri;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.media3.common.C;
import androidx.media3.datasource.DataSource;
import androidx.media3.datasource.DataSpec;
import androidx.media3.datasource.TransferListener;

import org.json.JSONObject;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * BONYX CipherDataSource — AES-256-GCM
 */
public class BonyxCipherDataSource implements DataSource {

    // ── .bonyx v2 header ──────────────────────
    private static final byte[] BONYX_MAGIC     = {0x42, 0x4F, 0x4E, 0x59, 0x58, 0x02}; // "BONYX\x02"
    private static final int    NONCE_LEN_FIELD = 4;    // 4-byte big-endian uint32
    private static final int    EXPECTED_NONCE  = 12;   // 96-bit nonce for GCM
    private static final int    GCM_TAG_BITS    = 128;  // 128-bit auth tag

    // ── Cipher ────────────────────────────────
    private static final String TRANSFORMATION  = "AES/GCM/NoPadding";
    private static final String ALGORITHM       = "AES";

    // ── Fields ────────────────────────────────
    private final DataSource downstream;
    private final String     workerUrl;
    private final String     telegramUserId;
    private final String     videoId;

    private Uri              openedUri;
    private InputStream      rawStream;

    private byte[]           aesKey;
    private byte[]           baseNonce;

    private byte[]           plaintextBuffer  = new byte[0];
    private int              bufferReadPos    = 0;
    private int              bufferLimit      = 0;
    private int              chunkIndex       = 0;
    private boolean          endOfStream      = false;

    public BonyxCipherDataSource(
            @NonNull DataSource downstream,
            @NonNull String workerUrl,
            @NonNull String telegramUserId,
            @NonNull String videoId) {
        this.downstream     = downstream;
        this.workerUrl      = workerUrl;
        this.telegramUserId = telegramUserId;
        this.videoId        = videoId;
    }

    @Override
    public void addTransferListener(@NonNull TransferListener transferListener) {
        downstream.addTransferListener(transferListener);
    }

    @Override
    public long open(@NonNull DataSpec dataSpec) throws IOException {
        openedUri   = dataSpec.uri;
        chunkIndex  = 0;
        endOfStream = false;
        bufferReadPos = bufferLimit = 0;

        downstream.open(dataSpec);
        rawStream = new DataSourceInputStream(downstream);

        byte[] magic = readExactly(rawStream, BONYX_MAGIC.length);
        for (int i = 0; i < BONYX_MAGIC.length; i++) {
            if (magic[i] != BONYX_MAGIC[i]) {
                throw new IOException("Not a valid .bonyx v2 file (bad magic).");
            }
        }

        byte[] nonceLenBytes = readExactly(rawStream, NONCE_LEN_FIELD);
        int nonceLen = ByteBuffer.wrap(nonceLenBytes).order(ByteOrder.BIG_ENDIAN).getInt();
        if (nonceLen != EXPECTED_NONCE) {
            throw new IOException("Unexpected nonce length in header: " + nonceLen);
        }

        baseNonce = readExactly(rawStream, nonceLen);

        KeyPayload kp = fetchKeyFromWorker(telegramUserId, videoId);
        aesKey    = kp.key;
        baseNonce = kp.nonce;   

        return C.LENGTH_UNSET;  
    }

    @Override
    public int read(@NonNull byte[] output, int offset, int length) throws IOException {
        if (length == 0) return 0;

        while (bufferReadPos >= bufferLimit) {
            if (endOfStream) return C.RESULT_END_OF_INPUT;
            if (!decryptNextChunk()) {
                endOfStream = true;
                return C.RESULT_END_OF_INPUT;
            }
        }

        int available = bufferLimit - bufferReadPos;
        int toCopy    = Math.min(available, length);
        System.arraycopy(plaintextBuffer, bufferReadPos, output, offset, toCopy);
        bufferReadPos += toCopy;
        return toCopy;
    }

    @Override
    public void close() throws IOException {
        try {
            if (rawStream != null) {
                rawStream.close();
                rawStream = null;
            }
        } finally {
            downstream.close();
            if (aesKey   != null) java.util.Arrays.fill(aesKey,    (byte) 0);
            if (baseNonce != null) java.util.Arrays.fill(baseNonce, (byte) 0);
        }
    }

    @Nullable @Override public Uri getUri() { return openedUri; }
    // THE ROGUE BRACKET WAS HERE. IT HAS BEEN DELETED.

    private boolean decryptNextChunk() throws IOException {
        byte[] lenBytes = new byte[4];
        int got = 0;
        while (got < 4) {
            int r = rawStream.read(lenBytes, got, 4 - got);
            if (r == -1) return false;   
            got += r;
        }

        int chunkLen = ByteBuffer.wrap(lenBytes).order(ByteOrder.BIG_ENDIAN).getInt();
        if (chunkLen <= 0 || chunkLen > 4 * 1024 * 1024) {
            throw new IOException("Corrupt .bonyx chunk length: " + chunkLen);
        }

        byte[] ciphertextAndTag = readExactly(rawStream, chunkLen);
        byte[] chunkNonce = baseNonce.clone();
        ByteBuffer idxBuf = ByteBuffer.allocate(4).order(ByteOrder.BIG_ENDIAN);
        idxBuf.putInt(chunkIndex);
        byte[] idxBytes = idxBuf.array();
        for (int i = 0; i < 4; i++) {
            chunkNonce[EXPECTED_NONCE - 4 + i] ^= idxBytes[i];
        }

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(
                Cipher.DECRYPT_MODE,
                new SecretKeySpec(aesKey, ALGORITHM),
                new GCMParameterSpec(GCM_TAG_BITS, chunkNonce)
            );
            plaintextBuffer = cipher.doFinal(ciphertextAndTag);
            bufferReadPos   = 0;
            bufferLimit     = plaintextBuffer.length;
            chunkIndex++;
            return true;
        } catch (GeneralSecurityException e) {
            throw new IOException("AES-GCM authentication failed on chunk " + chunkIndex, e);
        }
    }

    private KeyPayload fetchKeyFromWorker(String tgId, String vidId) throws IOException {
        String endpoint = workerUrl.replaceAll("/$", "") + "/key";
        HttpURLConnection conn = (HttpURLConnection) new URL(endpoint).openConnection();
        try {
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(8_000);
            conn.setReadTimeout(10_000);

            String reqBody = "{\"telegram_id\":\"" + tgId + "\",\"video_id\":\"" + vidId + "\"}";
            conn.getOutputStream().write(reqBody.getBytes(StandardCharsets.UTF_8));

            int status = conn.getResponseCode();
            if (status == 403) throw new IOException("VIP access required to play this video.");
            if (status == 404) throw new IOException("Video ID not found on key server.");
            if (status != 200) throw new IOException("Key server returned HTTP " + status);

            byte[] respBytes = conn.getInputStream().readAllBytes();
            JSONObject obj   = new JSONObject(new String(respBytes, StandardCharsets.UTF_8));

            long expiresAt = obj.optLong("expires_at", Long.MAX_VALUE);
            if (System.currentTimeMillis() / 1000 > expiresAt) {
                throw new IOException("Key payload has expired — reopen the video to retry.");
            }

            byte[] key   = hexToBytes(obj.getString("key"));
            byte[] nonce = hexToBytes(obj.getString("nonce"));  

            if (key.length != 32) throw new IOException("Invalid key length from server.");
            if (nonce.length != 12) throw new IOException("Invalid nonce length from server.");

            return new KeyPayload(key, nonce);

        } catch (org.json.JSONException e) {
            throw new IOException("Failed to parse key server response.", e);
        } finally {
            conn.disconnect();
        }
    }

    private static byte[] readExactly(InputStream in, int length) throws IOException {
        byte[] buf    = new byte[length];
        int    offset = 0;
        while (offset < length) {
            int read = in.read(buf, offset, length - offset);
            if (read == -1) throw new EOFException("Unexpected end of .bonyx stream.");
            offset += read;
        }
        return buf;
    }

    private static byte[] hexToBytes(String hex) {
        int    len  = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) (
                (Character.digit(hex.charAt(i),     16) << 4) |
                 Character.digit(hex.charAt(i + 1), 16)
            );
        }
        return data;
    }

    private static final class KeyPayload {
        final byte[] key;
        final byte[] nonce;
        KeyPayload(byte[] key, byte[] nonce) { this.key = key; this.nonce = nonce; }
    }

    private static final class DataSourceInputStream extends InputStream {
        private final DataSource source;
        private final byte[]     one = new byte[1];

        DataSourceInputStream(DataSource source) { this.source = source; }

        @Override
        public int read() throws IOException {
            int r = read(one, 0, 1);
            return (r == C.RESULT_END_OF_INPUT) ? -1 : (one[0] & 0xFF);
        }

        @Override
        public int read(@NonNull byte[] b, int off, int len) throws IOException {
            int r = source.read(b, off, len);
            return (r == C.RESULT_END_OF_INPUT) ? -1 : r;
        }
    }
}
