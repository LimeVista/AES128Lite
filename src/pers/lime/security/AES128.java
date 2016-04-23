package pers.lime.security;

import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



/**
 * <p>AES 算法 对称加密，密码学中的高级加密标准
 * <p>警告：
 * <p>	1.AES-128-CBC-NoPadding需要的加密的字符串长度必须是16的整倍数
 * <p>	2.AES-128 decrypt函数解密的字符串或byte[]的长度必须满足16的倍数
 * 
 * <p>示例：
 * <pre>{@code
 * AES128 aes=new AES128();
 * //加密
 * String s= aes.encryptEasy(AesType.aes_cbc_pkcs5, "src_Lime", "password");
 * //解密
 * String str = aes.decryptEasy(AesType.aes_cbc_pkcs5, s, "password");
 *}</pre>
 * @author Lime
 * <p>2016.04.22
 * 
 */
public class AES128 {

	/**
	 * <p>
	 * AES安全算法加密规则[枚举类型]
	 * <p>详细规则： 
	 * <p>	aes	AES默认加密规则  
	 * <p>	aes_ecb_pkcs5 AES-ECB加解密规则，填充规则PKCS5Padding
	 * <p>	aes_cbc_nopadding AES-CBC加解密规则，填充规则NoPadding
	 * <p>	aes_cbc_pkcs5 AES-CBC加解密规则，填充规则PKCS5Padding
	 * <p>	aes_cfb_nopadding AES-CFB加解密规则，填充规则NoPadding
	 * <p>	aes_cfb_pkcs5 AES-CFB加解密规则，填充规则PKCS5Padding
	 * 
	 * @author Lime 
	 * <p>2016.04.22
	 */
	public static enum AesType {
		
		/**
		 * AES默认加密规则 
		 */
		aes(0), 
		
		/**
		 * AES-ECB加解密规则，填充规则PKCS5Padding
		 */
		aes_ecb_pkcs5(1), 
		
		/**
		 * AES-CBC加解密规则，填充规则PKCS5Padding
		 */
		aes_cbc_nopadding(2),
		
		/**
		 * AES-CBC加解密规则，填充规则PKCS5Padding
		 */
		aes_cbc_pkcs5(3),
		
		/**
		 * AES-CFB加解密规则，填充规则NoPadding
		 */
		aes_cfb_nopadding(4),
		
		/**
		 * AES-CFB加解密规则，填充规则PKCS5Padding
		 */
		aes_cfb_pkcs5(5);

		private final int value;

		/**
		 * 获取枚举类型的值
		 * @return [int]返回值
		 */
		public int getValue() {
			return this.value;
		}

		/* 初始化枚举类型并且赋值 */
		private AesType(int value) {
			this.value = value;
		}
	};

	/**
	 * 说明此算法是AES
	 */
	public final static String ALGORITHM = "AES";

	/**
	 * 加密文本编码，保证兼容性
	 */
	private final static String ByteType = "UTF-8";

	private KeyGenerator kgen;
	private Cipher cipher;

	/**
	 * AES安全算法加密规则[字符串]
	 */
	private static String[] Algorithm = new String[] { "AES", "AES/ECB/PKCS5Padding", "AES/CBC/NoPadding",
			"AES/CBC/PKCS5Padding","AES/CFB/NoPadding","AES/CFB/PKCS5Padding" };

	/* AES-CBC所需加密初始化向量 */
	private final static byte[] IV = new byte[] { 0x4C, 0x49, 0x4D, 0x45, 0x6C, 0x69, 0x6D, 0x65, 0x00, 0x09, 0x00,
			0x04, 0x01, 0x09, 0x09, 0x06 };

	/**
	 * <p>
	 * 使用AES-128算法对数据进行加密
	 *
	 * @param aesType
	 *            [AesType]加密规则（模式），例如： AesType.aes   AES-128-ECB
	 *            AesType.aes_ecb_pkcs5   AES-128-ECB-PKS5Padding
	 * @param msg
	 *            [String]需要加密的字符串，AES-CBC-NoPadding模式下字符串长度必须为16的倍数！
	 * @param skey
	 *            [String]加密密钥，必须位16位密码
	 * @return [byte[]]得到密文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	public byte[] encrypt(AesType aesType, String msg, String skey)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

		/* 加密密钥处理 */
		byte[] keyBytes = skey.getBytes();

		return encrypt(aesType, msg, keyBytes);
	}
	
	
	/**
	 * <p>
	 * 使用AES-128算法对数据进行加密
	 *
	 * @param aesType
	 *            [AesType]加密规则（模式），例如： AesType.aes -> AES-128-ECB
	 *            AesType.aes_ecb_pkcs5 -> AES-128-ECB-PKS5Padding
	 * @param msg
	 *            [String]需要加密的字符串，AES-CBC-NoPadding模式下字符串长度必须为16的倍数！
	 * @param keyBytes
	 *            [byte[]]加密密钥，必须位16数组密码
	 * @return [byte[]]得到密文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private byte[] encrypt(AesType aesType, String msg, byte[] keyBytes)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

		/* 检测是否初始化和是否符合我们所需的初始化 ，如果aesType为空时，选择AES默认加密规则 */
		if (aesType == null)
			init(AesType.aes, keyBytes);
		else
			init(aesType, keyBytes);

		/* 解密密钥处理 ,这个地方无论是ECB/CFB/CBC模式，不管是Padding还是NoPadding,都和它无关！填AES就行了 */
		// SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");
		SecretKeySpec key = new SecretKeySpec(keyBytes, ALGORITHM);

		/* 完成初始化 ,CBC规则需要初始化向量IV */
		if (aesType == AesType.aes || aesType == AesType.aes_ecb_pkcs5)
			cipher.init(Cipher.ENCRYPT_MODE, key);
		else
			cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(IV));

		/* 执行加密 */
		byte[] encryptedText = cipher.doFinal(msg.getBytes(ByteType));

		return encryptedText;
	}

	/**
	 * <p>
	 * 使用AES-128算法对数据进行解密
	 * 
	 * @param aesType
	 *            [AesType]解密规则（模式），例如： AesType.aes 	 AES-128-ECB
	 *            AesType.aes_ecb_pkcs5 	 AES-128-ECB-PKS5Padding
	 * @param msg
	 *            [String]需要解密的字符串，字符串长度必须为16的倍数！
	 * @param skey
	 *            [String]解密密钥，必须位16位密码
	 * @return [byte[]]得到明文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	public byte[] decrypt(AesType aesType, byte[] msg, String skey) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		/* 解密密钥处理 */
		byte[] keyBytes = skey.getBytes();

		return decrypt(aesType, msg, keyBytes);
	}
	
	/**
	 * <p>
	 * 使用AES-128算法对数据进行解密
	 * 
	 * @param aesType
	 *            [AesType]解密规则（模式），例如： AesType.aes -> AES-128-ECB
	 *            AesType.aes_ecb_pkcs5 -> AES-128-ECB-PKS5Padding
	 * @param msg
	 *            [String]需要解密的字符串，字符串长度必须为16的倍数！
	 * @param keyBytes
	 *            [byte[]]解密密钥，必须位16数组密码
	 * @return [byte[]]得到明文
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws UnsupportedEncodingException
	 */
	private byte[] decrypt(AesType aesType, byte[] msg, byte[] keyBytes) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {

		/* 检测是否初始化和是否符合我们所需的初始化 ，如果aesType为空时，选择AES默认解密规则 */
		if (aesType == null)
			init(AesType.aes, keyBytes);
		else
			init(aesType, keyBytes);

		/* 解密密钥处理 ,这个地方无论是ECB/CFB/CBC模式，不管是Padding还是NoPadding,都和它无关！填AES就行了 */
		// SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");ALGORITHM
		SecretKeySpec key = new SecretKeySpec(keyBytes, ALGORITHM);

		/* 完成初始化 ,CBC规则需要初始化向量IV */
		if (aesType == AesType.aes || aesType == AesType.aes_ecb_pkcs5)
			cipher.init(Cipher.DECRYPT_MODE, key);
		else
			cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(IV));

		/* 执行解密 */
		byte[] decryptedText = cipher.doFinal(msg);

		return decryptedText;
	}
	
	/**
	 * <p>
	 * 使用AES-128算法对数据进行加密，并且用Base64加密后的字符串保留结果
	 * 
	 * @param aesType
	 *            [AesType]加密规则（模式），例如： AesType.aes  AES-128-ECB
	 *            AesType.aes_ecb_pkcs5  AES-128-ECB-PKS5Padding
	 * @param msg [String]需要加密的字符串，AES-CBC-NoPadding模式下字符串长度必须为16的倍数！
	 * @param skey 加密密钥，必须为16位！
	 * @return [String]得到经过Base64加密的密文
	 * @throws Exception
	 */
	public String encryptToBase64(AesType aesType, String msg, String skey) throws Exception {
		return Base64.encrypt(encrypt(aesType, msg, skey));
	}

	/**
	 * <p>
	 * 使用AES-128算法加密的Base64字符串对数据进行解密
	 * 
	 * @param aesType
	 *            [AesType]解密规则（模式），例如： AesType.aes   AES-128-ECB
	 *            AesType.aes_ecb_pkcs5   AES-128-ECB-PKS5Padding
	 * @param msg [String]需要解密的经过AES加密的Base64字符串。
	 * @param skey 解密密钥，必须为16位！
	 * @return [String]得到明文
	 * @throws Exception
	 */
	public String decryptFromBase64(AesType aesType, String msg, String skey) throws Exception {
		byte[] out = decrypt(aesType, Base64.decryptBytes(msg), skey);
		return new String(out, ByteType);
	}

	/**
	 * <p>
	 * 使用AES-128算法对数据进行加密，并且用Base64加密后的字符串保留结果
	 * 
	 * @param aesType
	 *            [AesType]加密规则（模式），例如： AesType.aes - AES-128-ECB
	 *            AesType.aes_ecb_pkcs5 - AES-128-ECB-PKS5Padding
	 * @param msg [String]需要加密的字符串，AES-CBC-NoPadding模式下字符串长度必须为16的倍数！
	 * @param skey 加密密钥，密钥任意长度。
	 * @return [String]得到经过Base64加密的密文
	 * @throws Exception
	 */
	public String encryptEasy(AesType aesType, String msg, String skey) throws Exception {
		/* 加密密钥处理 */
		byte[] keyBytes = new Hash().encode("MD5", skey);

		/*加密并且转化为Base64*/
		return Base64.encrypt(encrypt(aesType, msg, keyBytes));

	}

	/**
	 * <p>
	 * 使用AES-128算法加密的Base64字符串对数据进行解密
	 * 
	 * @param aesType
	 *            [AesType]解密规则（模式），例如： AesType.aes  AES-128-ECB
	 *            AesType.aes_ecb_pkcs5  AES-128-ECB-PKS5Padding
	 * @param msg [String]需要解密的经过AES加密的Base64字符串。
	 * @param skey 解密密钥，任意长度。
	 * @return [String]得到明文
	 * @throws Exception
	 */
	public String decryptEasy(AesType aesType, String msg, String skey) throws Exception {
		/* 解密密钥处理 */
		byte[] keyBytes = new Hash().encode("MD5", skey);

		byte[] out = decrypt(aesType, Base64.decryptBytes(msg), keyBytes);

		return new String(out,ByteType);
	}

	/* 初始化工作 */
	private void init(AesType aesType, byte[] key) throws NoSuchAlgorithmException, NoSuchPaddingException {
		// 初始化keyGen,这个地方无论是ECB/CFB/CBC模式，不管是Padding还是NoPadding,都和它无关！填AES就行了
		// kgen = KeyGenerator.getInstance("AES");
		kgen = KeyGenerator.getInstance(ALGORITHM);

		/* 不设置可能无法解密，靠!确保windows/Linux系统下一致 */
		SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
		secureRandom.setSeed(key);

		kgen.init(128, secureRandom);
		// 初始化cipher
		cipher = Cipher.getInstance(Algorithm[aesType.getValue()]);
	}
}
