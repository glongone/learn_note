package com.encryption.aes;

import javax.crypto.*;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;


/**
 * AES 原始加密方式
 * 简单实现初步加密
 */
public class AESDemo {

    // 定义密钥
    static final String ALGORITHM = "AES";
    // 设置编码
    static Charset charset = Charset.forName("UTF-8");

    // 生成密钥
    public static SecretKey generateKey() throws NoSuchAlgorithmException{
        // 获取密钥发生器实例
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        // 创建随机密码实例
        SecureRandom secureRandom = new SecureRandom();
        // 初始化密码
        keyGenerator.init(secureRandom);
        // 产生密钥，密钥生成
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey;
    }

    // 对当前内容进行加密，加密内容 content 加密方式 secretKey
    public static byte[] encrypt(String content, SecretKey secretKey){
        return aes(content.getBytes(charset),Cipher.ENCRYPT_MODE,secretKey);
    }

    // 解密解密内容 contentArray 解密方式 secretKey
    public static String decrypt(byte[] contentArray, SecretKey secretKey) {
        byte[] result =  aes(contentArray,Cipher.DECRYPT_MODE,secretKey);
        return new String(result,charset);
    }

    // 实现加密和解密（原始加密）
    private static byte[] aes(byte[] contentArray, int mode, SecretKey secretKey) {
        byte[] result = null;
        try {
            // 获取 Cipher 密码实例
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            // 初始化 Cipher 实例。设置执行模式以及加密密钥
            cipher.init(mode, secretKey);
            // 执行加密
            result = cipher.doFinal(contentArray);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch ( IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        // 返回密文字符集
        return result;
    }

    public static void main(String[] args) {
        String content = "AES加密测试";
        SecretKey secretKey;
        try {
            // 获取当前时间点
            long timeStart = System.currentTimeMillis();
            // 生成密钥
            secretKey = generateKey();
            byte[] encryptResult = encrypt(content, secretKey);
            long timeEnd = System.currentTimeMillis();
            System.out.println("加密后的结果为：" + new String(encryptResult, charset));
            // 解密的密钥需要与加密使用同一密钥
            String decryptResult = decrypt(encryptResult,secretKey);
            System.out.println("解密后的结果为：" + decryptResult);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


}

/**
 * 加密后的结果为：ފcbf����J(?pL
 * 解密后的结果为：AES加密测试
 */
