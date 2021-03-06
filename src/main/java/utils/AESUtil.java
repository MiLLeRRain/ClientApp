package utils;

import org.apache.commons.lang3.RandomStringUtils;

import java.util.Base64;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;

/**
 * Copyright (c) 2019-present ShenBao
 * @homepage https://github.com/ShenBao/rsa-aes-utils
 * @author ShenBao <shenbaoone@gmail.com>
 */
public class AESUtil {
    /**
     * 随机生成秘钥
     * @return String
     */
    public static String createAesKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(128);
            //要生成多少位，只需要修改这里即可 128, 192 或 256
            SecretKey sk = kg.generateKey();
            byte[] b = sk.getEncoded();
            String k = byteToHexString(b);
            return k;
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 随机生成 IV
     * @return String
     */
    public static String createAesIv() {
        String iv = RandomStringUtils.randomAlphanumeric(16);
        return iv.toLowerCase();
    }
    /**
     * byte 数组转化为 16 进制字符串
     * @param bytes
     * @return String
     */
    public static String byteToHexString(byte[] bytes) {
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < bytes.length; i++) {
            String strHex = Integer.toHexString(bytes[i]);
            if (strHex.length() > 3) {
                sb.append(strHex.substring(6));
            } else {
                if (strHex.length() < 2) {
                    sb.append("0" + strHex);
                } else {
                    sb.append(strHex);
                }
            }
        }
        return sb.toString();
    }
    /**
     * 加密 CBC
     * @param data String
     * @param key String
     * @param iv String
     * @return String
     */
    public static String encryptByCBC(String data, String key, String iv) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            int blockSize = cipher.getBlockSize();
            byte[] dataBytes = data.getBytes();
            int plaintextLength = dataBytes.length;
            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }
            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.ENCRYPT_MODE, keyspec, ivspec);
            byte[] encrypted = cipher.doFinal(plaintext);
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 解密 CBC
     * @param data String
     * @param key String
     * @param iv String
     * @return String
     */
    public static String decryptByCBC(String data, String key, String iv) throws Exception {
        try {
            byte[] encrypted1 = Base64.getDecoder().decode(data);
            Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            IvParameterSpec ivspec = new IvParameterSpec(iv.getBytes());
            cipher.init(Cipher.DECRYPT_MODE, keyspec, ivspec);
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original);
            return originalString.trim();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 加密 ECB
     * @param data String
     * @param key String
     * @return String
     */
    public static String encryptByECB(String data, String key) throws Exception {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            int blockSize = cipher.getBlockSize();
            byte[] dataBytes = data.getBytes();
            int plaintextLength = dataBytes.length;
            if (plaintextLength % blockSize != 0) {
                plaintextLength = plaintextLength + (blockSize - (plaintextLength % blockSize));
            }
            byte[] plaintext = new byte[plaintextLength];
            System.arraycopy(dataBytes, 0, plaintext, 0, dataBytes.length);
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keyspec);
            byte[] encrypted = cipher.doFinal(plaintext);
            return Base64.getEncoder().encodeToString(encrypted);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
    /**
     * 解密 ECB
     * @param data String
     * @param key String
     * @return String
     */
    public static String decryptByECB(String data, String key) throws Exception {
        try {
            byte[] encrypted1 = Base64.getDecoder().decode(data);
            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            SecretKeySpec keyspec = new SecretKeySpec(key.getBytes(), "AES");
            cipher.init(Cipher.DECRYPT_MODE, keyspec);
            byte[] original = cipher.doFinal(encrypted1);
            String originalString = new String(original);
            return originalString.trim();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }
}