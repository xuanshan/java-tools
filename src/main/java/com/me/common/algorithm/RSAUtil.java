package com.me.common.algorithm;

import com.me.common.util.Base64Utils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.*;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Abloomy on 2017/9/1.
 */
public class RSAUtil {

    private static final String KEY_METHOD = "RSA";
    private static final String DEFAULT_CHARSET = "utf-8";

    public static String readKeyFile(File file ){
        try {
            return readKeyFile(new FileInputStream(file));
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String readKeyFile(InputStream inputStream){
        BufferedReader br = null;
        try{
            br = new BufferedReader(new InputStreamReader(inputStream,DEFAULT_CHARSET));
            StringBuffer sb = new StringBuffer();
            String str = null;
            while((str=br.readLine())!=null){
                if(str.indexOf("-BEGIN")>-1||str.indexOf("-END")>-1){
                    continue;
                }else{
                    sb.append(str);
                    sb.append("\n");
                }
            }
            br.close();
            return sb.toString();
        }catch(Exception e){
            e.printStackTrace();
        }finally {
            if(br!=null){
                try {
                    br.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
        return null;
    }

    /**
     * 获取公钥
     * */
    public static RSAPublicKey loadPublicKey(String publicKeyStr){
        try {
            byte[] buffer = Base64Utils.decodeFromString(publicKeyStr);
            KeyFactory keyFactory= KeyFactory.getInstance(KEY_METHOD);
            X509EncodedKeySpec keySpec= new X509EncodedKeySpec(buffer);
            RSAPublicKey rsaPublicKey = (RSAPublicKey) keyFactory.generatePublic(keySpec);
            return rsaPublicKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 获取私钥
     * */
    public static RSAPrivateKey loadPrivateKey(String privateKey){
        try{
            byte[] buffer = Base64Utils.decodeFromString(privateKey);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(buffer);
            KeyFactory keyFactory = KeyFactory.getInstance(KEY_METHOD);
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
            return rsaPrivateKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 公钥加密
     * */
    public static byte[] encryptByPublic(RSAPublicKey publicKey, byte[] deCodeData){
        if(null==publicKey){
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(KEY_METHOD,new BouncyCastleProvider());
            cipher.init(Cipher.ENCRYPT_MODE,publicKey);
            byte[] output = cipher.doFinal(deCodeData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            //明文长度非法
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 私钥解密
     *
     * */
    public static byte[] decryptByPrivate(RSAPrivateKey privateKey,byte[] enCodeData){
        if(null==privateKey){
            return null;
        }
        try {
            Cipher cipher = Cipher.getInstance(KEY_METHOD,new BouncyCastleProvider());
            cipher.init(Cipher.DECRYPT_MODE,privateKey);
            byte[] output = cipher.doFinal(enCodeData);
            return output;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        }
        return null;
    }
    /**
     * 私钥加密
     * */
    public static byte[] encryptByPrivate(byte[] privKeyInByte, byte[] data) {
        try {
            PKCS8EncodedKeySpec priv_spec = new PKCS8EncodedKeySpec(privKeyInByte);
            KeyFactory mykeyFactory = KeyFactory.getInstance(KEY_METHOD);
            PrivateKey privKey = mykeyFactory.generatePrivate(priv_spec);
            Cipher cipher = Cipher.getInstance(mykeyFactory.getAlgorithm());
            cipher.init(Cipher.ENCRYPT_MODE, privKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }
    /**
     * 公钥解密
     * */
    public static byte[] decryptByPublic(byte[] pubKeyInByte, byte[] data) {
        try {
            KeyFactory mykeyFactory = KeyFactory.getInstance(KEY_METHOD);
            X509EncodedKeySpec pub_spec = new X509EncodedKeySpec(pubKeyInByte);
            PublicKey pubKey = mykeyFactory.generatePublic(pub_spec);
            Cipher cipher = Cipher.getInstance(mykeyFactory.getAlgorithm());
            cipher.init(Cipher.DECRYPT_MODE, pubKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            return null;
        }
    }
    /**
     * 分片
     * */
    public static byte[][] convertByteToMtu(byte[] data,RSAKey key){
        try {
            int key_len = key.getModulus().bitLength()/8;
            int len = data.length;
            int arr = len / key_len;
            byte[][] resB = new byte[arr][];
            for (int i = 0; i < resB.length; i++) {
                resB[i] = new byte[512];
                System.arraycopy(data, i * 512, resB[i], 0, 512);
            }
            return resB;
        }catch (Exception e){
            return null;
        }
    }

    /**
     * 公钥加密
     */
    public static byte[][] encryptByPublicKeyMtu(byte[] data, RSAPublicKey publicKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        int key_len = publicKey.getModulus().bitLength() / 8;
        byte[][] datas = splitByte(data, key_len - 11);
        byte[][] bytes = new byte[datas.length][];
        int i=0;
        for (byte[] s: datas) {
            byte[] enBytes = cipher.doFinal(s);
            bytes[i] = enBytes;
            i++;
        }
        return bytes;
    }
    /**
     * 私钥加密
     */
    public static byte[][] encryptByPrivateKeyMtu(byte[] data, RSAPrivateKey privateKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);
        // 模长
        int key_len = privateKey.getModulus().bitLength() / 8;
        // 加密数据长度 <= 模长-11
        byte[][] datas = splitByte(data, key_len - 11);
        byte[][] bytes = new byte[datas.length][];
        //如果明文长度大于模长-11则要分组加密
        int i=0;
        for (byte[] s: datas) {
            byte[] enBytes = cipher.doFinal(s);
            bytes[i] = enBytes;
            i++;
        }
        return bytes;
    }
    /**
     * 私钥解密
     * */
    public static byte[] decryptByPrivateKeyMtu(byte[][] data, RSAPrivateKey privateKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        int key_len = privateKey.getModulus().bitLength() / 8;
        byte[] resB = new byte[data.length*key_len];
        byte[][] arrays = data;
        int d = 0;
        for(int i=0;i<arrays.length;i++ ){
            byte[] arr = arrays[i];
            byte[] oneB = cipher.doFinal(arr);
            if(i==(arrays.length-1)){
                d = oneB.length;
            }
            System.arraycopy(oneB,0,resB,i*(key_len-11),oneB.length);
        }
        if(d>0){
            byte[] bytes = new byte[(data.length-1)*(key_len-11)+d];
            System.arraycopy(resB,0,bytes,0,bytes.length);
            return bytes;
        }else{
            return resB;
        }
    }
    /**
     * 公钥解密
     * */
    public static byte[] decryptByPublicKeyMtu(byte[][] data, RSAPublicKey publicKey)
            throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);
        int key_len = publicKey.getModulus().bitLength() / 8;
        byte[] resB = new byte[data.length*(key_len-11)];
        byte[][] arrays = data;
        int i=0;
        for(byte[] arr : arrays){
            byte[] oneB = cipher.doFinal(arr);
            System.arraycopy(oneB,0,resB,i*(key_len-11),oneB.length);
        }
        return resB;
    }

    public static byte[] witeBytes(byte[][] data)throws Exception{
        if(null==data){
            return null;
        }
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for(int i=0;i<data.length;i++) {
            byte[] b = data[i];
            bos.write(b);
        }
        byte[] b = bos.toByteArray();
        bos.close();
        return b;
    }

    private static byte[][] splitByte(byte[] data, int len) {
        try {
            int x = data.length / len;
            int y = data.length % len;
            int z = 0;
            if (y != 0) {
                z = 1;
            }
            byte[][] bytes = new byte[x+z][];
            for (int i = 0; i < x + z; i++) {
                if (i == x + z - 1 && y != 0) {
                    bytes[i] = new byte[y];
                    System.arraycopy(data,i*len,bytes[i],0,y);
                } else {
                    bytes[i] = new byte[len];
                    System.arraycopy(data,i*len,bytes[i],0,len);
                }
            }
            return bytes;
        }catch(Exception e){
            return null;
        }
    }

}
