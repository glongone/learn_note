package com.encryption.md5;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * MD5 加密算法实现
 * 哈希函数,java内部自带
 */
public class MD5Demo {
    public static void main(String[] args) {
        System.out.println(md5("123"));
    }

    // 定义一个 md5 加密的方法
    public static String md5(String input){
        // 定义一个字节数组，用于加密,私密数组
        byte[] secretBytes = null;
        try {
            // 用任意大小的安全单向哈希函数数据，并输出一个固定长度的哈希值
            // 实现 MD5 算法的消息摘要对象。
            MessageDigest md = MessageDigest.getInstance("MD5");
            // 对字符串进行加密
            md.update(input.getBytes());
            // 获取加密后的数据
            secretBytes = md.digest();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("加密失败");
            e.printStackTrace();
        }
        // 将加密后的数据转换为16进制数字
        String md5code = new BigInteger(1, secretBytes).toString(16);
        // 如果生成数字未满32位，需要在前面补上一个0
        for (int i = 0; i < 32 - md5code.length(); i++) {
            md5code = "0" + md5code;
        }
        return md5code;
    }
}
/**
 * 使用规则：源码
 * try {
 *  *     md.update(toChapter1);
 *  *     MessageDigest tc1 = md.clone();
 *  *     byte[] toChapter1Digest = tc1.digest();
 *  *     md.update(toChapter2);
 *  *     ...etc.
 *  * } catch (CloneNotSupportedException cnse) {
 *  *     throw new DigestException("couldn't make digest of partial content");
 *  * }
 */
