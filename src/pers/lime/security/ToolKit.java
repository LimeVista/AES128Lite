package pers.lime.security;

/**
 * @author Lime
 * <p>2016.04.23
 */
public class ToolKit {

	/**
	 * 将2进制byte[]流转化为16进制字符串
	 * @param bytes [byte[]]被转换源
	 * @return [String]转换后的字符串
	 */
	public static String bytes2Hex(byte[] bytes) {
		String output = "";
		String tmp = null;
		for (int i = 0; i < bytes.length; i++) {
			tmp = Integer.toHexString(bytes[i] & 0XFF);
			tmp = tmp.length() == 1 ? tmp + "0" : tmp;
			output += tmp;
		}
		return output;
	}

	/**
	 * 将16进制字符串转换为2进制byte[]流
	 * @param hexs [String]需要转换的16进制字符串
	 * @return [byte[]]转换后的bytes流
	 */
	public static byte[] hex2Bytes(String hexs) {
		byte[] output = new byte[hexs.length() >> 1];
		char[] chs = hexs.toCharArray();
		for (int i = 0, c = 0; i < chs.length; i += 2, c++)
			output[c] = (byte) (Integer.parseInt(new String(chs, i, 2), 16));
		return output;
	}
}
