package pers.lime.security;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;

/**
 * <p>这是一个调用信息摘要算法(Hash)的类。
 * <p>通过此类可以调用各种hash算法，并得到加密后的文本或值。
 * 
 * <p>示例：
 * 		
 *<pre>{@code
 *Hash hash = new Hash();
 *String hashCode = hash.sha256("123456");
 *}</pre>
 * @author Lime
 * <p>2016.04.22
 */
public class Hash {

	private MessageDigest msgDigest;
	private String ByteType = "UTF-8";

	/**
	 * MD5加密算法
	 * 
	 * @param msg
	 *            [String]被加密源
	 * @return [String]获得加密文本
	 */
	public String md5(String msg) {
		return bytes2Hex(encode("MD5", msg));
	}

	/**
	 * SHA-1加密算法
	 * 
	 * @param msg
	 *            [String]被加密源
	 * @return [String]获得加密文本
	 */
	public String sha1(String msg) {
		return bytes2Hex(encode("SHA-1", msg));
	}

	/**
	 * SHA-256加密算法
	 * 
	 * @param msg
	 *            [String]被加密源
	 * @return [String]获得加密文本
	 */
	public String sha256(String msg) {
		return bytes2Hex(encode("SHA-256", msg));
	}

	/**
	 * SHA-384加密算法
	 * 
	 * @param msg
	 *            [String]被加密源
	 * @return [String]获得加密文本
	 */
	public String sha384(String msg) {
		return bytes2Hex(encode("SHA-384", msg));
	}

	/**
	 * SHA-512加密算法
	 * 
	 * @param msg
	 *            [String]被加密源
	 * @return [String]获得加密文本
	 */
	public String sha512(String msg) {
		return bytes2Hex(encode("SHA-512", msg));
	}

	/**
	 * CRC32加密算法
	 * 
	 * @param msg
	 *            [String]被加密源
	 * @return [long]加密值
	 */
	public long crc32(String msg) {
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
	 * @param algorithm
	 *            [String]加密算法类型
	 * @param msg
	 *            [String]需要加密的内容
	 * @return [byte[]]数组 加密数组
	 */
	public byte[] encode(String algorithm, String msg) {
		byte[] code = null;
		try {
			msgDigest = MessageDigest.getInstance(algorithm);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			code = msgDigest.digest(msg.getBytes(ByteType));
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return code;
	}

	/**
	 * 将byte[]类型转化为字符串类型
	 * 
	 * @param bytes
	 *            [byte[]]源
	 * @return [String]转化后的字符串
	 */
	private String bytes2Hex(byte[] bytes) {
		String output = "";
		String tmp = null;
		for (int i = 0; i < bytes.length; i++) {
			tmp = Integer.toHexString(bytes[i] & 0XFF);
			tmp = tmp.length() == 1 ? tmp + "0" : tmp;
			output += tmp;
		}
		return output;
	}
}
