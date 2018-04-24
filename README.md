# AES 128 Lite for Java [![](https://jitpack.io/v/LimeVista/AES128Lite.svg)](https://jitpack.io/#LimeVista/AES128Lite)
对SHA-128、Hash 算法进行简单封装，方便使用

## How to
* To get a Git project into your build:
* Step 1. Add the JitPack repository to your build file
```groovy
allprojects {
	repositories {
		...
		maven { url 'https://jitpack.io' }
	}
}
```

* Step 2. Add the dependency
```groovy
 compile 'com.github.LimeVista:AES128Lite:0.1.1'
```

* Or Maven
```xml
<repositories>
		<repository>
		    <id>jitpack.io</id>
		    <url>https://jitpack.io</url>
		</repository>
</repositories>
...
<dependency>
	  <groupId>com.github.LimeVista</groupId>
	  <artifactId>AES128Lite</artifactId>
	  <version>0.1.1</version>
</dependency>
```

## 简单使用实例：
```java
AES128 aes=new AES128(AES128.ECB|AES128.PKCS5Padding);

//加密
String s= aes.encryptBase64("src_Lime", "password");

//解密
String str = aes.decryptBase64(s, "password");

```
 2016.4.24 by LimeVista
