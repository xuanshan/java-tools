package com.me.common.util;

import org.apache.commons.codec.net.URLCodec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * /** 字符串工具集合
 */
public class StringUtil {

    private static final String PASSWORD_CRYPT_KEY = "cindaportal";
    private final static String DES = "DES";
    public static Pattern pattern = Pattern.compile("#\\{[\\s|\\S]*?\\}");


    public static String toStr(String[] strs) {
        if (strs == null) {
            return null;
        }

        if (strs.length == 1) {
            return strs[0];
        }

        StringBuffer sb = new StringBuffer();
        sb.append(strs[0]);
        for (int i = 1; i < strs.length; i++) {
            sb.append(".").append(strs[i]);
        }
        return sb.toString();
    }

    public static boolean isEmpty(Object obj) {
        return obj == null || "".equals(obj.toString().trim());
    }

    public static String trim(String str) {
        return str == null ? "" : str.trim();
    }

    public static String delmarkertoupper(String mac) {
        if ((mac == null) || (mac.length() <= 0))
            return null;
        if (mac.contains(":"))
            mac = mac.replace(":", "");
        return mac.replaceAll(":", "").toUpperCase();
    }

    public static String delmarkertolower(String mac) {
        if ((mac == null) || (mac.length() <= 0))
            return null;
        if (mac.contains(":"))
            mac = mac.replace(":", "");
        return mac.replaceAll(":", "").toLowerCase();
    }



    public static String addmarkertolower(Object mac) {
        if (mac == null) {
            return null;
        }
        return addmarkertolower(mac.toString());
    }

    /**
     * 加密
     *
     * @param src 数据源
     * @param key 密钥，长度必须是的倍数
     * @return 返回加密后的数据
     * @throws Exception
     */
    public static byte[] encrypt(byte[] src, byte[] key) throws Exception {
        // DES算法要求有一个可信任的随机数源
        SecureRandom sr = new SecureRandom();
        // 从原始密匙数据创建DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key);
        // 创建一个密匙工厂，然后用它把DESKeySpec转换成
        // 一个SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);
        // Cipher对象实际完成加密操作
        Cipher cipher = Cipher.getInstance(DES);
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.ENCRYPT_MODE, securekey, sr);
        // 现在，获取数据并加密
        // 正式执行加密操作
        return cipher.doFinal(src);
    }

    /**
     * 解密
     *
     * @param src 数据源
     * @param key 密钥，长度必须是的倍数
     * @return 返回解密后的原始数据
     * @throws Exception
     */
    public static byte[] decrypt(byte[] src, byte[] key) throws Exception {
        // DES算法要求有一个可信任的随机数源
        SecureRandom sr = new SecureRandom();
        // 从原始密匙数据创建一个DESKeySpec对象
        DESKeySpec dks = new DESKeySpec(key);
        // 创建一个密匙工厂，然后用它把DESKeySpec对象转换成
        // 一个SecretKey对象
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(DES);
        SecretKey securekey = keyFactory.generateSecret(dks);
        // Cipher对象实际完成解密操作
        Cipher cipher = Cipher.getInstance(DES);
        // 用密匙初始化Cipher对象
        cipher.init(Cipher.DECRYPT_MODE, securekey, sr);
        // 现在，获取数据并解密
        // 正式执行解密操作
        return cipher.doFinal(src);
    }

    /**
     * 密码解密
     *
     * @param data
     * @return
     * @throws Exception
     */
    public final static String decrypt(String data) throws Exception {
        return new String(decrypt(hex2byte(data.getBytes()), PASSWORD_CRYPT_KEY.getBytes()));
    }

    /**
     * 密码加密
     *
     * @param password
     * @return
     * @throws Exception
     */
    public final static String encrypt(String password) throws Exception {
        return byte2hex(encrypt(password.getBytes(), PASSWORD_CRYPT_KEY.getBytes()));
    }

    /**
     * 二行制转字符串
     *
     * @param b
     * @return
     */
    public static String byte2hex(byte[] b) throws Exception {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1)
                hs = hs + "0" + stmp;
            else
                hs = hs + stmp;
        }
        return hs.toUpperCase();
    }

    public static byte[] hex2byte(byte[] b) throws Exception {
        if ((b.length % 2) != 0)
            throw new IllegalArgumentException("长度不是偶数");
        byte[] b2 = new byte[b.length / 2];
        for (int n = 0; n < b.length; n += 2) {
            String item = new String(b, n, 2);
            b2[n / 2] = (byte) Integer.parseInt(item, 16);
        }
        return b2;
    }

    /**
     * BASE64解密
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static byte[] decryptBASE64(String key) throws Exception {
        return (new BASE64Decoder()).decodeBuffer(key);
    }

    /**
     * BASE64加密
     *
     * @param key
     * @return
     * @throws Exception
     */
    public static String encryptBASE64(byte[] key) throws Exception {
        return (new BASE64Encoder()).encodeBuffer(key);
    }

    /**
     * 分割字符串 分隔符：逗號
     *
     * @param
     * @return
     * @throws Exception
     */
    public static String[] splitString(String string) throws Exception {
        if ((string == null) || (string.length() <= 0))
            return null;
        return string.split(",");
    }

    /**
     * 分割字符串 分隔符
     *
     * @param string :帶分割的字符串
     * @param regex  :分隔符
     * @return
     * @throws Exception
     */
    public static String[] splitString(String string, String regex) {
        if ((string == null) || (string.length() <= 0))
            return null;
        return string.split(regex);
    }

    public static String urlDecode(String str, String charset) {
        if (isEmpty(str)) {
            return null;
        }
        try {
            return new URLCodec().decode(str, charset);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String replase(Object param, String str) {
        if (str == null) {
            return str;
        }
        Matcher match = pattern.matcher(str);
        while (match.find()) {
            String key = match.group();
        }

        return str;
    }

    public static String getFormatDate(long time, String pattern) {
        SimpleDateFormat sdf = null;
        try {
            Date date = new Date(time);
            if (pattern == null) {
                sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            } else {
                sdf = new SimpleDateFormat(pattern);
            }
            return sdf.format(date);
        } catch (Exception e) {

        }
        return null;
    }

    /**
     * 获取UUID
     *
     * @return
     * @date Aug 1, 2016 5:47:34 PM
     */
    public static String getUuid() {
        return UUID.randomUUID().toString().replaceAll("-", "");
    }

    /**
     * 判断字符串内容是否是数字
     *
     * @param value
     * @return
     * @date Aug 1, 2016 5:47:43 PM
     */
    public static boolean isInteger(String value) {
        try {
            Integer.parseInt(value);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * 将日期字符串转成long类型的数据
     * 例如：2016-08-24 14:04:11 ----> 20160824140411
     *
     * @param dateStr
     * @return 如果参数合法，转换成对应的long类型数据，否则返回-1
     */
    public static long parseDateStr2Long(String dateStr) {
        if (StringUtil.isEmpty(dateStr)) {
            return -1;
        }
        dateStr = dateStr.replaceAll("^-|\\W|:$", "");
        return Long.parseLong(dateStr);
    }

    public boolean ipCheck(String text) {
        if (text != null && !text.isEmpty()) {
            // 定义正则表达式
            String regex = "^(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[1-9])\\."
                    + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\." + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)\\."
                    + "(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|\\d)$";
            // 判断ip地址是否与正则表达式匹配
            if (text.matches(regex)) {
                // 返回判断信息
                return true;
            } else {
                // 返回判断信息
                return false;
            }
        }
        // 返回判断信息
        return false;
    }

    public static String fillZeroInFrontOfCharactor(int number, int length) {
        return String.format("%0" + length + "d", number);
    }
}
