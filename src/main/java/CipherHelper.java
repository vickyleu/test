import org.apache.commons.codec.binary.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.Key;
import java.security.Security;

public class CipherHelper {
    private static Cipher aes() {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            return Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        } catch (Exception e) {
            System.out.println("获取加密实例Cipher失败！" + e.getMessage());
        }
        return null;
    }
    public static byte[] encrypt(byte[] bArr, String key) {
        try {
            Key secretKey = CipherHelper.patchKey(key);
            Cipher cipher = CipherHelper.aes();
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(bArr);
        } catch (Exception e) {
        }
        return "".getBytes();
    }
    /**
     * 根据密钥对指定的密文cipherText进行解密.
     *
     * @param cipherText 密文
     * @return 解密后的明文.
     */
    public static final String decrypt(String cipherText, String key) {
        try {
            Key secretKey = CipherHelper.patchKey(key);
            Cipher cipher = CipherHelper.aes();
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] result = cipher.doFinal(cipherText.getBytes());
            return new String(result);
        } catch (Exception e) {
            System.out.println("Exception = [" + e.getMessage() + "]");
        }
        return null;
    }

    public static String toHexCipherString(String str, String str2) {
        return CipherHelper.toHexCipherString(CipherHelper.encrypt(str.getBytes(), str2));
    }

    public static String hexCipherString2String(String hex, String key) {
        String str = null;
        try {
            String regex = "^/(//)*(?=[^/]|$)";
//            System.out.println("hex= [" + hex + "]");
            hex = hex.replaceAll(regex, "");
//            System.out.println("hex= [" + hex + "]");
            byte[] b = Hex.decodeHex(hex.toCharArray());
            str = new String(b);
        } catch (Exception e) {
            e.printStackTrace();
        }
        System.out.println("str = [" + str + "]");
        return decrypt(str, key);
    }

    /* renamed from: a */
    public static Key patchKey(String str) throws UnsupportedEncodingException {
        if (str == null) {
            str = "0000";
        }
        String value = (str + "0000000000000000000000000000");
        return new SecretKeySpec(value.getBytes("UTF-8"), "AES");
    }

    /* renamed from: a */
    public static String toHexCipherString(byte[] bArr) {
        StringBuffer stringBuffer = new StringBuffer();
        for (byte b : bArr) {
            String toHexString = Integer.toHexString(b & 255);
            if (toHexString.length() == 1) {
                toHexString = '0' + toHexString;
            }
            stringBuffer.append(toHexString.toUpperCase());
        }
        return stringBuffer.toString();
    }
}
