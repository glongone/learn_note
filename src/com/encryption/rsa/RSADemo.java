package com.encryption.rsa;


import com.sun.org.apache.xml.internal.security.utils.Base64;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA 加密算法
 *
 */
public class RSADemo {

    // 公钥、私钥生成算法
    private final static String KEY_ALGORITHM = "RSA";

    // 数据签名算法
    private static final String SIGN_ALGORITHM = "SHA1withRSA";
    // 公钥
    private static final String PUBLIC_KEY = "publicKey";
    // 私钥
    private static final String PRIVATE_KEY = "privateKey";
    // 秘钥长度，2的指数倍，越大越安全，一般1024或2048
    private static final int KEY_LENGTH = 512;

    // 初始化密钥
    public static Map<String, Key> initKey() throws NoSuchAlgorithmException {
        // 实例化秘钥生成器
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(KEY_ALGORITHM);
        // 初始化秘钥长度，KEY_LENGTH
        keyPairGenerator.initialize(KEY_LENGTH);
        // 获取秘钥对
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        // 获取RSA公钥
        RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();
        // 获取RSA私钥
        RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();

        // 创建 map 接受数据以及密钥
        Map<String, Key> keyMap = new HashMap<String, Key>();
        // 将公钥私钥加入
        keyMap.put(PUBLIC_KEY,rsaPublicKey);
        keyMap.put(PRIVATE_KEY,rsaPrivateKey);

        return keyMap;
    }

    // 获取公钥
    public static RSAPublicKey getPublicKey(Map<String, Key> keyMap) {
        return (RSAPublicKey) keyMap.get(PUBLIC_KEY);
    }

    // 获取私钥
    public static RSAPrivateKey getPrivateKey(Map<String, Key> keyMap) {
        return (RSAPrivateKey) keyMap.get(PRIVATE_KEY);
    }

    // 使用私钥对数据进行签名
    public static byte[] signatureByPrivate(String data, RSAPrivateKey rsaPrivateKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // 使用给定的编码密钥(私钥 ASN.1编码)创建一个新的钥匙，钥匙执行PKCS #8标准
        // 对数组进行复制，防止后续修改
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(rsaPrivateKey.getEncoded());
        // 返回一个转换的KeyFactory对象指定算法的公钥/私钥。
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);

        // 获取私钥
        PrivateKey privateKey = keyFactory.generatePrivate(encodedKeySpec);

        // 使用签名算法实例化Signature签名对象，用于生产和验证数字签名
        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        // 使用签名私钥进行初始化
        signature.initSign(privateKey);
        // 更新需要签名的数据 data数据，待签署数据
        signature.update(data.getBytes());
        // 进行签名
        byte[] signed = signature.sign();

        return signed;
    }

    // 使用公钥对签名的数据进行校验
    public static boolean verifyByPublicKey(String data, byte[] bytes, RSAPublicKey rsaPublicKey)
            throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        // 使用给定的编码密钥(公钥 ASN.1)创建一个新的钥匙，钥匙执行X.509标准
        // 对数组进行复制，防止后续修改
        X509EncodedKeySpec encodedKeySpec = new X509EncodedKeySpec(rsaPublicKey.getEncoded());
        // 实例化KeyFactory
        KeyFactory keyFactory = KeyFactory.getInstance(KEY_ALGORITHM);
        // 获取签名公钥
        PublicKey publicKey = keyFactory.generatePublic(encodedKeySpec);

        Signature signature = Signature.getInstance(SIGN_ALGORITHM);
        // 初始化此对象以进行验证
        signature.initVerify(publicKey);
        // 更新签名数据
        signature.update(data.getBytes());
        boolean verified = signature.verify(bytes);

        return verified;
    }


    public static void main(String[] args) {
        String msg = "Hello World";
        try {
            Map<String, Key> keyMap = initKey();
            RSAPrivateKey privateKey = getPrivateKey(keyMap);
            RSAPublicKey publicKey = getPublicKey(keyMap);
            System.out.println("签名前的数据--->" + msg);
            // 执行签名
            byte[] signedMsg = signatureByPrivate(msg,privateKey);
            System.out.println("密钥的长度--->" + KEY_LENGTH);
            System.out.println("签名后数据长度--->" + signedMsg.length * 8);
            System.out.println("签名后的数据--->" + Base64.encode(signedMsg));
            // 校验签名
            boolean verified = verifyByPublicKey(msg, signedMsg, publicKey);
            System.out.println("校验--->" + verified);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }

}


/**
 * 签名前的数据--->Hello World
 * 密钥的长度--->512
 * 签名后数据长度--->512
 * 签名后的数据--->iWxKh+pupsPZ5hBbfw2Qw4pSNvvdhBlzLQLWshwIrm3FGbcUf1x+5GSznFZpl1aSD7FYo89Ft//M
 * ZHTbybZvHw==
 * 校验--->true
 */
