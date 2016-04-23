package pers.lime.test;


import pers.lime.security.AES128;
import pers.lime.security.AES128.AesType;
import pers.lime.security.Base64;
import pers.lime.security.Hash;

public class Test {
	public static void main(String[] args) {
		Hash hash = new Hash();
		System.out.println(hash.md5("123456"));
		System.out.println(hash.crc32("123456"));
		
		AES128 aes=new AES128();
		try {
			String s = Base64.encrypt(aes.encrypt(AesType.aes_ecb_pkcs5, "Lime", "1234567812345678"));
			byte[] bs= aes.encrypt(AesType.aes_ecb_pkcs5, "Lime", "1234567812345678");
			System.out.println(s);
			String outx=new String(aes.decrypt(AesType.aes_ecb_pkcs5, bs, "1234567812345678"));
			System.out.println(outx);
			String s2= aes.encryptToBase64(AesType.aes_ecb_pkcs5, "Lime", "1234567812345678");
			System.out.println(s2);
			System.out.println( aes.decryptFromBase64(AesType.aes_ecb_pkcs5, s2, "1234567812345678"));
			String s3= aes.encryptEasy(AesType.aes_cfb_nopadding, "Lime", "123");
			System.out.println(s3);
			System.out.println( aes.decryptEasy(AesType.aes_cfb_nopadding, s3, "123"));
		} catch (Exception e) {
			e.printStackTrace();
		} 
	}
}
