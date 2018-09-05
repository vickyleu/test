import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.Key;
import java.security.Security;

/* renamed from: com.frame.walker.b.a */
public class CipherHelper {
    /* renamed from: a */

    /* renamed from: a */
    private static Cipher aes() {
        try {
            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            return Cipher.getInstance("AES/ECB/PKCS7Padding", "BC");
        } catch (Exception e) {
            System.out.println("获取加密实例Cipher失败！" + e.getMessage());
        }
        return null;
    }

    /* renamed from: a */
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
        Key secretKey = CipherHelper.patchKey(key);
        try {
            Cipher cipher = CipherHelper.aes();
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
//            BASE64Decoder decoder = new BASE64Decoder();
//            byte[] c = decoder.decodeBuffer(cipherText);
//            byte[] result = cipher.doFinal(c);
            byte[] result = cipher.doFinal(cipherText.getBytes("UTF-8"));
            String plainText = new String(result,"UTF-8");
//            String plainText = new String(result, "UTF-8");
            return plainText;
        } catch (Exception e) {
            System.out.println("Exception = [" + e.getMessage() + "]");
        }
        return null;
    }


    /* renamed from: a */
    public static String toHexCipherString(String str, String str2) {
        return CipherHelper.toHexCipherString(CipherHelper.encrypt(str.getBytes(), str2));
    }

    public static String hexCipherString2String(String hex, String key) {
        String str = null;
        try {
            str = hexString2String(hex);
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return decrypt(str, key);
    }

    public static String hexString2String(String hex) throws UnsupportedEncodingException {
        return new String(hexStringToBytes(hex), "utf-8");
    }

    private static byte charToByte(char c) {
        return (byte) "0123456789ABCDEF".indexOf(c);
    }

    public static byte[] hexStringToBytes(String hexString) {
        if (hexString == null || hexString.equals("")) {
            return null;
        }
        hexString = hexString.toUpperCase();
        int length = hexString.length() / 2;
        char[] hexChars = hexString.toCharArray();
        byte[] d = new byte[length];
        for (int i = 0; i < length; i++) {
            int pos = i * 2;
            d[i] = (byte) (charToByte(hexChars[pos]) << 4 | charToByte(hexChars[pos + 1]));

        }
        return d;
    }

    public static String hexString2binaryString(String hexString) {
        if (ParameterSignUtil.isEmpty(hexString)) {
            return null;
        }
        String binaryString = "";
        for (int i = 0; i < hexString.length(); i++) {
            //截取hexStr的一位
            String hex = hexString.substring(i, i + 1);
            //通过toBinaryString将十六进制转为二进制
            String binary = Integer.toBinaryString(Integer.parseInt(hex, 16));
            //因为高位0会被舍弃，先补上4个0
            String tmp = "0000" + binary;
            //取最后4位，将多补的0去掉
            binaryString += tmp.substring(tmp.length() - 4);
        }
        return binaryString;
    }


    /* renamed from: a */
    public static Key patchKey(String str) {
        String str2 = str;
        if (str2 == null) {
            str2 = "0000";
        }
        String f = String.valueOf(str2) + "0000000000000000000000000000";

        return new SecretKeySpec(f.getBytes(Charset.forName("UTF-8")), "AES");

//
//        byte[] raw = null;
//        try {
//            byte[] keys = f.getBytes("UTF-8");
//            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
//            SecureRandom sr = SecureRandom.getInstance("SHA1PRNG", "SUN");
//            sr.setSeed(keys);
//            keyGenerator.init(128, sr);
//            SecretKey skey = keyGenerator.generateKey();
//            raw = skey.getEncoded();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//        return new SecretKeySpec(raw, "AES");
    }

    /* renamed from: a */
    public static String toHexCipherString(byte[] bArr) {
        StringBuilder stringBuffer = new StringBuilder();
        for (byte b : bArr) {
            String toHexString = Integer.toHexString(b & 255);
            if (toHexString.length() == 1) {
                toHexString = String.valueOf('0') + toHexString;
            }
            stringBuffer.append(toHexString.toUpperCase());
        }
        return stringBuffer.toString();
    }
}
