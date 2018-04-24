package me.limeice.common.function.algorithm.security;

import org.jetbrains.annotations.NotNull;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * <p>AES 算法 对称加密，密码学中的高级加密标准
 * <p>警告：
 * <p>	1.AES-128-CBC-NoPadding需要的加密的字符串长度必须是16的整倍数
 * <p>	2.AES-128 decrypt函数解密的字符串或byte[]的长度必须满足16的倍数
 * <p>
 * <p>示例：
 * <pre>{@code
 * AES128Base aes=new AES128Base(AES128Base.ECB|AES128Base.PKCS5Padding);
 * //加密
 * String s= aes.encrypt(msg, keyBytes);
 * //解密
 * String str = aes.decrypts(msg, keyBytes);
 * }</pre>
 *
 * @author Lime
 * <p>2016.04.22 update 2018.03.16
 */
@SuppressWarnings({"unused", "WeakerAccess"})
public class AES128Base {

    /**
     * No Mode.
     */
    public static final int NONE = 0x00;

    /**
     * Cipher Block Chaining Mode.
     */
    public static final int CBC = 0x10;

    /**
     * Cipher Feedback Mode.
     */
    public static final int CFB = 0x20;

    /**
     * Electronic Codebook Mode.
     */
    public static final int ECB = 0x30;

    /**
     * Output Feedback Mode.
     */
    public static final int OFB = 0x40;

    /**
     * No padding.
     */
    public static final int NoPadding = 0x00;

    /**
     * This padding for block ciphers is described in
     * Block Encryption Algorithms in the W3C's
     * "XML Encryption Syntax and Processing" document.
     */
    public static final int ISO10126Padding = 0x01;

    /**
     * The padding scheme described in RSA Laboratories,
     * "PKCS #5: Password-Based Encryption Standard,"
     * version 1.5, November 1993.
     */
    public static final int PKCS5Padding = 0x02;

    /**
     * The padding scheme defined in the SSL Protocol Version 3.0.
     */
    public static final int SSL3Padding = 0x03;

    /**
     * 说明此算法是AES
     */
    public final static String ALGORITHM = "AES";

    /**
     * 加密文本编码，保证兼容性
     */
    public final static String BYTE_TYPE = "UTF-8";

    protected final static String[] MODES = new String[]{"NONE", "CBC", "CFB", "ECB", "OFB"};
    protected final static String[] PADDING = new String[]{"NoPadding", "ISO10126Padding", "PKCS5Padding", "SSL3Padding"};


    /* AES-CBC所需加密初始化向量 */
    protected volatile byte[] IV = new byte[]{0x4C, 0x49, 0x4D, 0x45, 0x6C, 0x69, 0x6D, 0x65,
            0x00, 0x09, 0x00, 0x04, 0x01, 0x09, 0x09, 0x06};

    /* 算法 */
    protected String algorithm;

    /* 是否为CBC模式 */
    protected boolean isCBC = false;

    public AES128Base(int aesType) {
        algorithm = getAlgorithm(aesType);
    }

    /**
     * 设置IV向量
     *
     * @param iv 向量
     */
    public void setIV(byte[] iv) {
        if (iv.length != 16)
            throw new RuntimeException("iv length is 128 bit！");
        else {
            IV = null;
            IV = Arrays.copyOf(iv, 16);
        }
    }

    /**
     * <p>
     * 使用AES-128算法对数据进行加密
     *
     * @param msg      加密数据，如果NoPadding，加密数据长度必须为16的倍数！
     * @param keyBytes 解密密钥，必须位16位密码
     * @return 得到密文
     */
    public byte[] encrypt(@NotNull byte[] msg, @NotNull byte[] keyBytes)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec key = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(algorithm);
        if (!isCBC)
            cipher.init(Cipher.ENCRYPT_MODE, key);
        else
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));
        return cipher.doFinal(msg);
    }

    /**
     * <p>
     * 使用AES-128算法对数据进行解密
     *
     * @param msg      需要解密的数据，数据长度必须为16的倍数！
     * @param keyBytes 解密密钥，必须位16位密码
     * @return 得到明文
     */
    public byte[] decrypt(@NotNull byte[] msg, @NotNull byte[] keyBytes)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec key = new SecretKeySpec(keyBytes, ALGORITHM);
        Cipher cipher = Cipher.getInstance(algorithm);
        if (!isCBC)
            cipher.init(Cipher.DECRYPT_MODE, key);
        else
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));
        return cipher.doFinal(msg);
    }

    private String getAlgorithm(int aesType) {
        int mode = aesType >> 4;
        isCBC = (mode == CBC >> 4);
        return String.format("AES/%s/%s", MODES[mode], PADDING[aesType % 16]);
    }
}