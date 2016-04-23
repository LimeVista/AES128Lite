package pers.lime.security;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * <p>这是Base64编码类。用于加密文本和解密Base64字符串
 *
 * @author Lime 
 * <p>2016.04.22 
 *
 */
public class Base64 {

	public final static String charSet = "UTF-8";

	/**
	 * 加密为Base64编码格式流
	 * 
	 * @param bytes
	 *            [byte[]]需要加密的byte[]流
	 * @return [String]返回加密后的字符串
	 */
	public static String encrypt(byte[] bytes) {
		return bytes != null ? new BASE64Encoder().encode(bytes) : null;
	}

	/**
	 * 加密为Base64编码格式流
	 * 
	 * @param s
	 *            [String]需要加密的字符串
	 * @return [String]返回加密后的字符串
	 * @throws UnsupportedEncodingException
	 */
	public static String encrypt(String s) throws UnsupportedEncodingException {
		return encrypt(s.getBytes(charSet));
	}

	/**
	 * 解密Base64字符串
	 * @param s [String]需要解密的字符串
	 * @return [String]返回解密后的字符串
	 * @throws IOException
	 */
	public static String decrypt(String s) throws IOException {
		byte[] b = null;
		String result = null;
		if (s != null) {
			BASE64Decoder decoder = new BASE64Decoder();
			b = decoder.decodeBuffer(s);
			result = new String(b, charSet);
		}
		return result;
	}
	
	/**
	 * 解密Base64字符串
	 * @param s [String]需要解密的字符串
	 * @return [byte[]]返回解密后的Byte数组
	 * @throws IOException
	 */
	public static byte[] decryptBytes(String s) throws IOException {
		byte[] b = null;
		if (s != null) {
			BASE64Decoder decoder = new BASE64Decoder();
			b = decoder.decodeBuffer(s);
		}
		return b;
	}
}