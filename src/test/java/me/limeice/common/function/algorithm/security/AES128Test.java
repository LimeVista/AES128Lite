package me.limeice.common.function.algorithm.security;

import org.junit.Before;
import org.junit.Test;

import me.limeice.common.function.BytesUtils;

import static org.junit.Assert.assertEquals;


@SuppressWarnings({"SpellCheckingInspection", "ConstantConditions"})
public class AES128Test {

    private AES128 aesCbc = new AES128(AES128.CBC | AES128.ISO10126Padding);

    private AES128 aesEcb = new AES128(AES128.ECB | AES128.PKCS5Padding);

    private static final byte[] iv = new byte[]{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
            0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    private static final String MSG = "0123456789ABCDEF";

    private static final String SKEY = "Lime";

    private static final byte[] KEY_BYTES = new byte[]{(byte) 0xFC, (byte) 0x1C, (byte) 0xEB, (byte)
            0xF0, (byte) 0x2D, (byte) 0xC2, (byte) 0xEE, (byte) 0x68, (byte) 0x65, (byte) 0x5F, (byte) 0x3E,
            (byte) 0x7B, (byte) 0xF1, (byte) 0xB8, (byte) 0x42, (byte) 0x30};

    private static final String SMSG_ECB = "5faf450bd7925bf9deb073a20824f635fb3f1554e6f0f0efc8e0bc39c5f7ad15";

    private static final String SMSG_CBC = "0551359fee241bca3d2259e2f91f07110cb743161a4d6783dba8ca6017881d25";

    public AES128Test() {
        aesCbc.setIV(iv);
    }

    @Before
    public void setUp() {

    }

    private static void log(String msg) {
        System.out.println("AES128Test->" + msg);
    }

    @Test
    public void encrypt() throws Exception {
        byte[] bs = aesEcb.encrypt(MSG, KEY_BYTES);
        String sMsg = BytesUtils.toHexString(bs);
        assertEquals(SMSG_ECB, sMsg);
        byte[] aesBs = aesCbc.encrypt(MSG, KEY_BYTES);
        String sMsg2 = BytesUtils.toHexString(aesBs);
        log("sMsg1->" + sMsg + ";sMsg2->" + sMsg2);
    }

    @Test
    public void encryptEasy() throws Exception {
        String sMsg = aesEcb.encryptBase64(MSG, KEY_BYTES);
        String sMsg2 = aesCbc.encryptBase64(MSG, KEY_BYTES);
        log("sMsg1->" + sMsg + ";sMsg2->" + sMsg2);

        String sMsg3 = aesEcb.encryptBase64(MSG, SKEY);
        String sMsg4 = aesCbc.encryptBase64(MSG, SKEY);
        log("sMsg3->" + sMsg3 + ";sMsg4->" + sMsg4);
        assertEquals(sMsg, sMsg3);
    }

    @Test
    public void decrypt() throws Exception {
        byte[] bs = aesEcb.decrypt(BytesUtils.hexStringToBytes(SMSG_ECB), KEY_BYTES);
        String sMsg = new String(bs, "UTF-8");
        assertEquals(MSG, sMsg);
        byte[] bytes = BytesUtils.hexStringToBytes(SMSG_CBC);
        byte[] aesBs = aesCbc.decrypt(bytes, KEY_BYTES);
        String sMsg2 = new String(aesBs, "UTF-8");
        assertEquals(MSG, sMsg2);
        log("sMsg1->" + sMsg + ";sMsg2->" + sMsg2);
    }

    @Test
    public void decryptEasy() throws Exception {
        String msg1 = aesEcb.decryptBase64("X69FC9eSW/nesHOiCCT2Nfs/FVTm8PDvyOC8OcX3rRU=", KEY_BYTES);
        String msg2 = aesCbc.decryptBase64("BVE1n+4kG8o9Ilni+R8HEWd4mC5iZKXbenzEfeHZwnM=", KEY_BYTES);
        log("msg1->" + msg1 + ";msg2->" + msg2);
        String msg3 = aesEcb.decryptBase64("X69FC9eSW/nesHOiCCT2Nfs/FVTm8PDvyOC8OcX3rRU=", SKEY);
        String msg4 = aesCbc.decryptBase64("BVE1n+4kG8o9Ilni+R8HEWd4mC5iZKXbenzEfeHZwnM=", SKEY);
        log("msg3->" + msg3 + ";msg4->" + msg4);
        assertEquals(msg1, MSG);
        assertEquals(msg2, MSG);
        assertEquals(msg3, MSG);
        assertEquals(msg4, MSG);
    }
}