package me.limeice.common.function.algorithm.security;


import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;

import me.limeice.common.function.BytesUtils;
import org.jetbrains.annotations.NotNull;

/**
 * <p>这是一个调用信息摘要算法(Hash)的类。
 * <p>通过此类可以调用各种hash算法，并得到加密后的文本或值。
 * <p>
 * <p>示例：
 * <p>
 * <pre>{@code
 * String hashCode = Hash.sha256("123456");
 * }</pre>
 *
 * @author Lime
 *         <p>2016.04.22
 */
public final class Hash {

    private static final String ByteType = "UTF-8";

    /**
     * MD5加密算法
     *
     * @param msg 被加密源
     * @return 获得加密文本
     */
    @NotNull
    public static String md5(@NotNull String msg) {
        return BytesUtils.toHexString(encode("MD5", msg));
    }

    /**
     * MD5加密算法
     *
     * @param msg 被加密源
     * @return 获得加密数据
     */
    @NotNull
    public static byte[] md5ToBytes(@NotNull String msg) {
        return encode("MD5", msg);
    }

    /**
     * SHA-1加密算法
     *
     * @param msg 被加密源
     * @return 获得加密文本
     */
    @NotNull
    public static String sha1(@NotNull String msg) {
        return BytesUtils.toHexString(encode("SHA-1", msg));
    }

    /**
     * SHA-256加密算法
     *
     * @param msg 被加密源
     * @return 获得加密文本
     */
    @NotNull
    public static String sha256(@NotNull String msg) {
        return BytesUtils.toHexString(encode("SHA-256", msg));
    }

    /**
     * SHA-384加密算法
     *
     * @param msg 被加密源
     * @return 获得加密文本
     */
    @NotNull
    public static String sha384(@NotNull String msg) {
        return BytesUtils.toHexString(encode("SHA-384", msg));
    }

    /**
     * SHA-512加密算法
     *
     * @param msg 被加密源
     * @return 获得加密文本
     */
    @NotNull
    public static String sha512(@NotNull String msg) {
        return BytesUtils.toHexString(encode("SHA-512", msg));
    }

    /**
     * CRC32加密算法
     *
     * @param msg [String]被加密源
     * @return 加密值
     */
    public static long crc32(@NotNull String msg) {
        CRC32 crc = new CRC32();
        try {
            crc.update(msg.getBytes(ByteType));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return crc.getValue();
    }

    /**
     * 执行信息摘要算法加密
     *
     * @param algorithm [String]加密算法类型
     * @param msg       [String]需要加密的内容
     * @return 加密数组
     */
    @NotNull
    public static byte[] encode(@NotNull String algorithm, @NotNull String msg) {
        byte[] code;
        MessageDigest msgDigest;
        try {
            msgDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        try {
            code = msgDigest.digest(msg.getBytes(ByteType));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        return code;
    }

    /**
     * 执行信息摘要算法加密
     *
     * @param algorithm 加密算法类型
     * @param msg       需要加密的数据
     * @return 加密数组
     */
    @NotNull
    public static byte[] encode(@NotNull String algorithm, @NotNull byte[] msg) {
        byte[] code;
        MessageDigest msgDigest;
        try {
            msgDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            throw new RuntimeException(e.getMessage());
        }
        code = msgDigest.digest(msg);
        return code;
    }
}
