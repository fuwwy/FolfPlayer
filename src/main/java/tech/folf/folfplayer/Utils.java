package tech.folf.folfplayer;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.protobuf.ByteString;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

public class Utils {
    private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    public static byte[] toByteArray(BigInteger i) {
        byte[] array = i.toByteArray();
        if (array[0] == 0) array = Arrays.copyOfRange(array, 1, array.length);
        return array;
    }

    public static byte[] toByteArray(int i) {
        ByteBuffer buffer = ByteBuffer.allocate(4);
        buffer.putInt(i);
        return buffer.array();
    }

    public static String randomHexString(Random random, int length) {
        byte[] bytes = new byte[length / 2];
        random.nextBytes(bytes);
        return bytesToHex(bytes, 0, bytes.length, false, length);
    }

    public static String bytesToHex(byte[] bytes, int offset, int length, boolean trim, int minLength) {
        if (bytes == null) return "";

        int newOffset = 0;
        boolean trimming = trim;
        char[] hexChars = new char[length * 2];
        for (int j = offset; j < length; j++) {
            int v = bytes[j] & 0xFF;
            if (trimming) {
                if (v == 0) {
                    newOffset = j + 1;

                    if (minLength != -1 && length - newOffset == minLength)
                        trimming = false;

                    continue;
                } else {
                    trimming = false;
                }
            }

            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }

        return new String(hexChars, newOffset * 2, hexChars.length - newOffset * 2);
    }

    public static String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, 0, bytes.length, false, -1);
    }

    public static String bytesToHex(@org.jetbrains.annotations.NotNull ByteString bytes) {
        return bytesToHex(bytes.toByteArray());
    }

    public static byte[] hexToBytes(@NotNull String str) {
        int len = str.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2)
            data[i / 2] = (byte) ((Character.digit(str.charAt(i), 16) << 4) + Character.digit(str.charAt(i + 1), 16));
        return data;
    }


    @Contract("_, _, !null -> !null")
    public static String optString(@NotNull JsonObject obj, @NotNull String key, @Nullable String fallback) {
        JsonElement elm = obj.get(key);
        if (elm == null || !elm.getAsJsonPrimitive().isString()) return fallback;
        return elm.getAsString();
    }
}
