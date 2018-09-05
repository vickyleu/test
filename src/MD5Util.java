import org.apache.commons.codec.binary.Base64;

import java.security.MessageDigest;

public class MD5Util {
    public static String MD5Encode(String str) {
        if (ParameterSignUtil.isEmpty(str)) {
            return "";
        }
        try {
            String str2 = "";
            for (byte b : MessageDigest.getInstance("MD5").digest(str.getBytes("GBK"))) {
                StringBuilder stringBuilder;
                String toHexString = Integer.toHexString(b & 255);
                if (toHexString.length() == 1) {
                    stringBuilder = new StringBuilder();
                    stringBuilder.append("0");
                    stringBuilder.append(toHexString);
                    toHexString = stringBuilder.toString();
                }
                stringBuilder = new StringBuilder();
                stringBuilder.append(str2);
                stringBuilder.append(toHexString);
                str2 = stringBuilder.toString();
            }
            return str2;
        } catch (Exception e) {
            e.printStackTrace();
            return "";
        }
    }

    public static String cipher(String str) {
        return MD5Util.cipher(str, "UTF8");
    }

    /* renamed from: a */
    public static String cipher(String str, String charset) {
        try {
            MessageDigest instance = MessageDigest.getInstance("MD5");
            instance.update(str.getBytes(charset));
            return new String(Base64.encodeBase64(instance.digest()));
        } catch (Throwable e) {
            throw new RuntimeException("数据加密出现异常!", e);
        }
    }
}
