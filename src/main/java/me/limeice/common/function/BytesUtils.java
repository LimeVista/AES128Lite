package me.limeice.common.function;


import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

/**
 * 字节流处理工具
 * <pre>
 *     author: LimeVista(Lime)
 *     time  : 2018/03/16
 *     desc  : Bytes工具类
 *     github: https://github.com/LimeVista/EasyCommon
 * </pre>
 */
public final class BytesUtils {

    private BytesUtils() {
        throw new UnsupportedOperationException("Don't instantiate...");
    }

    /**
     * Convert byte array to hex string
     *
     * @param bytes byte array, eg:[0x1A,0x2C,0x3B]
     * @return hex string, eg: 1A2C3B
     */
    @NotNull
    public static String toHexString(@NotNull byte[] bytes) {
        if (bytes.length == 0)
            return "";
        StringBuilder builder = new StringBuilder();
        for (byte b : bytes) {
            String hv = Integer.toHexString(b & 0xFF);
            if (hv.length() < 2)
                builder.append(0);
            builder.append(hv);
        }
        return builder.toString();
    }

    /**
     * Convert byte to hex value
     *
     * @param b byte, eg: 8
     * @return hex value, eg: 0x08
     */
    @NotNull
    public static String convert(byte b) {
        String hv = Integer.toHexString(b & 0xFF);
        return hv.length() < 2 ? ("0x0" + hv) : ("0x" + hv);
    }

    /**
     * Convert byte array to hex values
     *
     * @param bytes byte array, eg: [8,1]
     * @return hex value, eg: [0x08, 0x01]
     */
    @NotNull
    public static String convert(@NotNull final byte[] bytes) {
        StringBuilder builder = new StringBuilder("[");
        int i = 0;
        for (; i < bytes.length - 1; i++)
            builder.append(convert(bytes[i])).append(", ");

        return builder.append(convert(bytes[i])).append(']').toString();
    }

    /**
     * Convert hex string to byte array
     *
     * @param hexString hex string eg: 1A2C3B
     * @return byte array eg:[0x1A,0x2C,0x3B]
     */
    @Nullable
    public static byte[] hexStringToBytes(@Nullable String hexString) {
        if (hexString == null || hexString.length() == 0)
            return null;
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i << 1;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));
        }
        return d;
    }

    /**
     * boolean value to byte
     *
     * @param value boolean value
     * @return byte
     */
    public static byte toBytes(boolean value) {
        return value ? (byte) 0x1 : (byte) 0x0;
    }

    /**
     * short value to byte array(length = 2)
     *
     * @param value short value
     * @return byte array(length = 2)
     */
    @NotNull
    public static byte[] toBytes(short value) {
        byte[] bs = new byte[2];
        bs[0] = (byte) (value & 0xFF);
        bs[1] = (byte) ((value >>> 8) & 0xFF);
        return bs;
    }

    /**
     * int value to byte array(length = 4)
     *
     * @param value int value
     * @return byte array(length = 4)
     */
    @NotNull
    public static byte[] toBytes(int value) {
        byte[] bs = new byte[4];
        bs[0] = (byte) (value & 0xFF);
        bs[1] = (byte) ((value >>> 8) & 0xFF);
        bs[2] = (byte) ((value >>> 16) & 0xFF);
        bs[3] = (byte) ((value >>> 24) & 0xFF);
        return bs;
    }

    /**
     * float value to byte array(length = 4)
     *
     * @param value int value
     * @return byte array(length = 4)
     */
    @NotNull
    public static byte[] toBytes(float value) {
        int val = Float.floatToRawIntBits(value);
        return toBytes(val);
    }

    /**
     * long value to byte array(length = 8)
     *
     * @param value long value
     * @return byte array(length = 8)
     */
    @NotNull
    public static byte[] toBytes(long value) {
        byte[] bs = new byte[8];
        bs[0] = (byte) (value & 0xFF);
        bs[1] = (byte) ((value >>> 8) & 0xFF);
        bs[2] = (byte) ((value >>> 16) & 0xFF);
        bs[3] = (byte) ((value >>> 24) & 0xFF);
        bs[4] = (byte) ((value >>> 32) & 0xFF);
        bs[5] = (byte) ((value >>> 40) & 0xFF);
        bs[6] = (byte) ((value >>> 48) & 0xFF);
        bs[7] = (byte) ((value >>> 56) & 0xFF);
        return bs;
    }

    /**
     * double value to byte array(length = 4)
     *
     * @param value int value
     * @return byte array(length = 4)
     */
    @NotNull
    public static byte[] toBytes(double value) {
        long val = Double.doubleToLongBits(value);
        return toBytes(val);
    }

    /**
     * boolean value put byte array
     *
     * @param bs    bytes
     * @param value boolean value
     * @param index bytes offset
     */
    public static void put(@NotNull byte[] bs, boolean value, int index) {
        bs[index] = (byte) (value ? 0x1 : 0x0);
    }

    /**
     * short value put byte array
     *
     * @param bs    bytes
     * @param value short value
     * @param index bytes offset
     */
    public static void put(@NotNull byte[] bs, short value, int index) {
        bs[index] = (byte) (value & 0xFF);
        bs[index + 1] = (byte) ((value >>> 8) & 0xFF);
    }

    /**
     * int value put byte array
     *
     * @param bs    bytes
     * @param value int value
     * @param index bytes offset
     */
    public static void put(@NotNull byte[] bs, int value, int index) {
        bs[index] = (byte) (value & 0xFF);
        bs[index + 1] = (byte) ((value >>> 8) & 0xFF);
        bs[index + 2] = (byte) ((value >>> 16) & 0xFF);
        bs[index + 3] = (byte) ((value >>> 24) & 0xFF);
    }

    /**
     * float value put byte array
     *
     * @param bs    bytes
     * @param value int value
     * @param index bytes offset
     */
    public static void put(@NotNull byte[] bs, float value, int index) {
        int val = Float.floatToIntBits(value);
        put(bs, val, index);
    }

    /**
     * long value put byte array
     *
     * @param bs    bytes
     * @param value long value
     * @param index bytes offset
     */
    public static void put(@NotNull byte[] bs, long value, int index) {
        bs[index] = (byte) (value & 0xFF);
        bs[index + 1] = (byte) ((value >>> 8) & 0xFF);
        bs[index + 2] = (byte) ((value >>> 16) & 0xFF);
        bs[index + 3] = (byte) ((value >>> 24) & 0xFF);
        bs[index + 4] = (byte) ((value >>> 32) & 0xFF);
        bs[index + 5] = (byte) ((value >>> 40) & 0xFF);
        bs[index + 6] = (byte) ((value >>> 48) & 0xFF);
        bs[index + 7] = (byte) ((value >>> 56) & 0xFF);
    }

    /**
     * double value put byte array
     *
     * @param bs    bytes
     * @param value int value
     * @param index bytes offset
     */
    public static void put(@NotNull byte[] bs, double value, int index) {
        long val = Double.doubleToLongBits(value);
        put(bs, val, index);
    }


    /**
     * get boolean from byte
     *
     * @param bs    bytes
     * @param index bs offset
     * @return value
     */
    public static boolean getBoolean(@NotNull byte[] bs, int index) {
        return bs[index] != 0;
    }

    /**
     * get short from byte array
     *
     * @param bs    bytes
     * @param index bs offset
     * @return value
     */
    public static short getShort(@NotNull byte[] bs, int index) {
        return (short) (
                (bs[index] & 0xFF) |
                        ((bs[index + 1] & 0xFF) << 8)
        );
    }

    /**
     * get int from byte array
     *
     * @param bs    bytes
     * @param index bs offset
     * @return value
     */
    public static int getInt(@NotNull byte[] bs, int index) {
        return (bs[index] & 0xFF) |
                ((bs[index + 1] & 0xFF) << 8) |
                ((bs[index + 2] & 0xFF) << 16) |
                ((bs[index + 3] & 0xFF) << 24);
    }

    /**
     * get float from byte array
     *
     * @param bs    bytes
     * @param index bs offset
     * @return value
     */
    public static float getFloat(@NotNull byte[] bs, int index) {
        return Float.intBitsToFloat(
                (bs[index] & 0xFF) | ((bs[index + 1] & 0xFF) << 8) |
                        ((bs[index + 2] & 0xFF) << 16) | ((bs[index + 3] & 0xFF) << 24)
        );
    }

    /**
     * get long from byte array
     *
     * @param bs    bytes
     * @param index bs offset
     * @return value
     */
    public static long getLong(@NotNull byte[] bs, int index) {
        return ((long) bs[index] & 0xFF) |
                ((long) (bs[1 + index] & 0xFF) << 8) |
                ((long) (bs[2 + index] & 0xFF) << 16) |
                ((long) (bs[3 + index] & 0xFF) << 24) |
                ((long) (bs[4 + index] & 0xFF) << 32) |
                ((long) (bs[5 + index] & 0xFF) << 40) |
                ((long) (bs[6 + index] & 0xFF) << 48) |
                ((long) (bs[7 + index] & 0xFF) << 56);
    }

    /**
     * get double from byte array
     *
     * @param bs    bytes
     * @param index bs offset
     * @return value
     */
    public static double getDouble(@NotNull byte[] bs, int index) {
        return Double.longBitsToDouble(((long) bs[index] & 0xFF) |
                ((long) (bs[1 + index] & 0xFF) << 8) |
                ((long) (bs[2 + index] & 0xFF) << 16) |
                ((long) (bs[3 + index] & 0xFF) << 24) |
                ((long) (bs[4 + index] & 0xFF) << 32) |
                ((long) (bs[5 + index] & 0xFF) << 40) |
                ((long) (bs[6 + index] & 0xFF) << 48) |
                ((long) (bs[7 + index] & 0xFF) << 56));
    }

    /**
     * get boolean from byte array
     *
     * @param b byte
     * @return value
     */
    public static boolean getBoolean(byte b) {
        return b != 0;
    }

    /**
     * get short from byte array
     *
     * @param bs bytes(length = 2)
     * @return value
     */
    public static short getShort(@NotNull byte[] bs) {
        return (short) (
                (bs[0] & 0xFF) |
                        ((bs[1] & 0xFF) << 8)
        );
    }

    /**
     * get int from byte array
     *
     * @param bs bytes(length = 4)
     * @return value
     */
    public static int getInt(@NotNull byte[] bs) {
        return (bs[0] & 0xFF) |
                ((bs[1] & 0xFF) << 8) |
                ((bs[2] & 0xFF) << 16) |
                ((bs[3] & 0xFF) << 24);
    }

    /**
     * get float from byte array
     *
     * @param bs bytes(length = 4)
     * @return value
     */
    public static float getFloat(@NotNull byte[] bs) {
        return Float.intBitsToFloat(
                (bs[0] & 0xFF) | ((bs[1] & 0xFF) << 8) |
                        ((bs[2] & 0xFF) << 16) | ((bs[3] & 0xFF) << 24)
        );
    }

    /**
     * get long from byte
     *
     * @param bs bytes(length = 8)
     * @return value
     */
    public static long getLong(@NotNull byte[] bs) {
        return ((long) bs[0] & 0xFF) |
                ((long) (bs[1] & 0xFF) << 8) |
                ((long) (bs[2] & 0xFF) << 16) |
                ((long) (bs[3] & 0xFF) << 24) |
                ((long) (bs[4] & 0xFF) << 32) |
                ((long) (bs[5] & 0xFF) << 40) |
                ((long) (bs[6] & 0xFF) << 48) |
                ((long) (bs[7] & 0xFF) << 56);
    }

    /**
     * get double from byte
     *
     * @param bs bytes(length = 8)
     * @return value
     */
    public static double getDouble(@NotNull byte[] bs) {
        return Double.longBitsToDouble(
                ((long) bs[0] & 0xFF) |
                        ((long) (bs[1] & 0xFF) << 8) |
                        ((long) (bs[2] & 0xFF) << 16) |
                        ((long) (bs[3] & 0xFF) << 24) |
                        ((long) (bs[4] & 0xFF) << 32) |
                        ((long) (bs[5] & 0xFF) << 40) |
                        ((long) (bs[6] & 0xFF) << 48) |
                        ((long) (bs[7] & 0xFF) << 56)
        );
    }

    /**
     * Convert char to byte
     *
     * @param c char
     * @return byte 0 1 2 3 4 5 6 7 8 9 A B C D E F
     */
    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }
}
