import com.sun.istack.internal.Nullable;
import org.apache.commons.codec.binary.Base64;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.Charset;
import java.text.SimpleDateFormat;
import java.util.*;

public class ParameterSignUtil {
    public static void main(String[] args) {
//        getParam1();
//        getParam2();

//        String str=asHex("12121212adjkdfjdj77sw92*&*(902ZHDS".getBytes());
//        hexStr2Str(str);


//        String source = "NjRGQzcwMjg5Nzk4REQyREQ1MEFGMDcyNDgzMTUxRkRBMjZCNDM5MzZCRkIyQzMxMzBGNUYyMEVCMTExMjdCRTdCM0NGREYyRjQ0RTE3NzVCRTY5NTU3RjcwQUIwRjMzQ0IxNTUyRjlDMzJDMzA5MzQwN0JBMDRCRDgyMEY0QzJBNTU1MTU1OTBGMUFEODVCRjUxQTVFRkY0MkNDRkVGODlCQjVGRThFMDA3MTZDQjlCMDlGQTNEM0VBMDg1NDFBMjdEOTk0NzlGMTM1MzAzNkMzQjdFN0U0Mzk0NjQ2NDlEN0Q5RUNBOTcxMjQxNTQ2N0EwQ0MwMTgwNEZBMzM2MjEwRTVERUQ4MDU3MzFCNDBCODkyRDUxRThGMUVBM0MzOUMyNkNGQUJDQzA0QTRBN0NERjBBMjQyQkFERTFCMzQ4N0NFOEY2MjREQ0JFMkRCOEIwMDNBRjZERDU1RkRDRDBDRDg5NDU2NDAxQzQ4NTBCNjU1RkM4ODc2MEQwMTA0RDI3ODFGQTY2Q0ZCNDZCMzU5OTZCMkIwQkVDNTkzMzcwQUVDNjAxN0Y5MjBBNjY4NDY1OEMxQUM2MUI3RTVCOURGOUVGMDk2NUQ0Q0Y2RjUwMUQ2OTk4NEQ2MUI4MzRBRjM5NTM2MkMyNjVFRTlCMEI5RkI4RDI0Q0Y1N0U0MTRFREI2QTk3RDI5RkQzNzdCRTJFRDFGN0FCMENGNTlBNUI5QzY0NERFNzQwMjQxNDczNkIwRDE4OEE0NDVEODUxQ0U5QzAzQ0E0NDI5RkFDOTM3QzY0MkU3NEI3RTUwQkQ%3D";
//        String md5 = "uZqv5Q3o96S9C%252B56a3RDOQ%253D%253D";
//
//        source="B82E9FE277176A2A3491661CD0943D91";
//        md5="2bIDNiz8GlzclcVAG9gybg==";
//
//        source = source.replace("+", "%2B")
//                .replace("=", "%3D")
//                .replaceAll("[\\s*\t\n\r]", "");
//        ;
//
//
//        md5 = md5.replace("+", "%2B")
//                .replace("=", "%3D")
//                .replaceAll("[\\s*\t\n\r]", "");

//        String decoded = new String(Base64.decodeBase64(source.getBytes(Charset.forName("utf-8"))));


        String source = "1241312121212";

//        String source ="NjRGQzcwMjg5Nzk4REQyREQ1MEFGMDcyNDgzMTUxRkRBMjZCNDM5MzZCRkIyQzMxMzBGNUYyMEVCMTExMjdCRTdCM0NGREYyRjQ0RTE3NzVCRTY5NTU3RjcwQUIwRjMzQ0IxNTUyRjlDMzJDMzA5MzQwN0JBMDRCRDgyMEY0QzJBNTU1MTU1OTBGMUFEODVCRjUxQTVFRkY0MkNDRkVGODlCQjVGRThFMDA3MTZDQjlCMDlGQTNEM0VBMDg1NDFBMjdEOTk0NzlGMTM1MzAzNkMzQjdFN0U0Mzk0NjQ2NDlEN0Q5RUNBOTcxMjQxNTQ2N0EwQ0MwMTgwNEZBMzM2MjEwRTVERUQ4MDU3MzFCNDBCODkyRDUxRThGMUVBM0MzOUMyNkNGQUJDQzA0QTRBN0NERjBBMjQyQkFERTFCMzQ4N0NFOEY2MjREQ0JFMkRCOEIwMDNBRjZERDU1RkRDRDBDRDg5NDU2NDAxQzQ4NTBCNjU1RkM4ODc2MEQwMTA0RDI3ODFGQTY2Q0ZCNDZCMzU5OTZCMkIwQkVDNTkzMzcwQUVDNjAxN0Y5MjBBNjY4NDY1OEMxQUM2MUI3RTVCOURGOUVGMDk2NUQ0Q0Y2RjUwMUQ2OTk4NEQ2MUI4MzRBRjM5NTM2MkMyNjVFRTlCMEI5RkI4RDI0Q0Y1N0U0MTRFREI2QTk3RDI5RkQzNzdCRTJFRDFGN0FCMENGNTlBNUI5QzY0NERFNzQwMjQxNDczNkIwRDE4OEE0NDVEODUxQ0U5QzAzQ0E0NDI5RkFDOTM3QzY0MkU3NEI3RTUwQkQ%3D";

        System.out.println("source = [" + source + "]");
        source = encrypt(source);
        System.out.println("source encrypt = [" + source + "]");
        source=decrypt(source);
        System.out.println("source decrypt = [" + source + "]");
        //        asHex("NjRGQzcwMjg5Nzk4REQyREQ1MEFGMDcyNDgzMTUxRkRBMjZCNDM5MzZCRkIyQzMxMzBGNUYyMEVCMTExMjdCRTdCM0NGREYyRjQ0RTE3NzVCRTY5NTU3RjcwQUIwRjMzQ0IxNTUyRjlDMzJDMzA5MzQwN0JBMDRCRDgyMEY0QzJBNTU1MTU1OTBGMUFEODVCRjUxQTVFRkY0MkNDRkVGODlCQjVGRThFMDA3MTZDQjlCMDlGQTNEM0VBMDg1NDFBMjdEOTk0NzlGMTM1MzAzNkMzQjdFN0U0Mzk0NjQ2NDlEN0Q5RUNBOTcxMjQxNTQ2N0EwQ0MwMTgwNEZBMzM2MjEwRTVERUQ4MDU3MzFCNDBCODkyRDUxRThGMUVBM0MzOUMyNkNGQUJDQzA0QTRBN0NERjBBMjQyQkFERTFCMzQ4N0NFOEY2MjREQ0JFMkRCOEIwMDNBRjZERDU1RkRDRDBDRDg5NDU2NDAxQzQ4NTBCNjU1RkM4ODc2MEQwMTA0RDI3ODFGQTY2Q0ZCNDZCMzU5OTZCMkIwQkVDNTkzMzcwQUVDNjAxN0Y5MjBBNjY4NDY1OEMxQUM2MUI3RTVCOURGOUVGMDk2NUQ0Q0Y2RjUwMUQ2OTk4NEQ2MUI4MzRBRjM5NTM2MkMyNjVFRTlCMEI5RkI4RDI0Q0Y1N0U0MTRFREI2QTk3RDI5RkQzNzdCRTJFRDFGN0FCMENGNTlBNUI5QzY0NERFNzQwMjQxNDczNkIwRDE4OEE0NDVEODUxQ0U5QzAzQ0E0NDI5RkFDOTM3QzY0MkU3NEI3RTUwQkQ%3D".getBytes());
//        hexStr2Str(decoded);


    }


    public static String encrypt(String source) {
        try {
            source = CipherHelper.toHexCipherString(source, "9048");
            String md5 = "";//= MD5Util.cipher(source);
            System.out.println("toHexCipherString = [" + source + "]");
            try {
                source = new String(Base64.encodeBase64(source.getBytes(Charset.forName("utf-8"))));
                md5 = URLEncoder.encode(MD5Util.cipher(source), "utf-8");
            } catch (UnsupportedEncodingException e2) {
                e2.printStackTrace();
            }
            System.out.println("URLEncoder = [" + md5 + "]");

            System.out.println("source = [" + source + "]");
            source=URLEncoder.encode(source, "utf-8");
            System.out.println("source = [" + source + "]");
            return source;
        } catch (Exception e) {
        }
        return "";
    }

    public static String decrypt(String source) {
        try {
            source = URLDecoder.decode(source, "utf-8");
            System.out.println("toHexCipherString URLDecoder = [" + source + "]");
            String decoded = new String(Base64.decodeBase64(source.getBytes(Charset.forName("utf-8"))));
            String realString = CipherHelper.hexCipherString2String(decoded, "9048");
//            source="AD5D1ABF9A744F344C5B27007FC9D229";
//            String realString = CipherHelper.hexCipherString2String(source, "9048");
            System.out.println("decrypt = [" + realString + "]");
            String resultMd5 = URLEncoder.encode(MD5Util.cipher(source), "utf-8");
            System.out.println("resultMd5 = [" + resultMd5 + "]");
            return realString;
        } catch (Exception e) {
        }
        return "";
    }

    public static HashMap<String, String> getParam1() {
        HashMap<String, String> hashMap = new HashMap();
        hashMap.put("dvcCode", "dvcCode");
        hashMap.put("charset", "GBK");
        hashMap.put("rtnType", "xml");
        hashMap.put("type", "xml");
        hashMap.put("data", "jsonParam");
        hashMap.put("svceName", "svceName");
        hashMap.put("sign", sign(hashMap, "dvcCode", "encryptKey"));
//        hashMap.put("sign", sign(hashMap, "dvcCode")); //todo otherwise
        return hashMap;
    }

    public static HashMap<String, String> getParam2() {
        HashMap<String, String> hashMap = new HashMap();
        hashMap.put("dvcCode", "dvcCode");
        hashMap.put("charset", "GBK");
        hashMap.put("rtnType", "json");
        hashMap.put("type", "json");
        hashMap.put("data", "jsonParam");
        hashMap.put("svceName", "svceName");
        hashMap.put("sign", sign(hashMap, "dvcCode", "encryptKey"));
//        hashMap.put("sign", sign(hashMap, "dvcCode"));//todo otherwise
        return hashMap;
    }

    /**
     * 十六进制字符串转换成字符串
     *
     * @param hexStr
     * @return String
     */
    public static String hexStr2Str(String hexStr) {
//        String toHexString = Integer.toHexString(b & 255);
        String str = "0123456789ABCDEF";
        char[] hexs = hexStr.toCharArray();
        byte[] bytes = new byte[hexStr.length() / 2];
        int n;
        for (int i = 0; i < bytes.length; i++) {
            n = str.indexOf(hexs[2 * i]) * 16;
            n += str.indexOf(hexs[2 * i + 1]);
            bytes[i] = (byte) (n & 255);
        }
        String result = new String(bytes);
        System.out.println("Str = [" + result + "]");
        return result;
    }

    private static final char[] HEX_CHARS = "0123456789abcdef".toCharArray();

    public static String asHex(byte[] buf) {
        char[] chars = new char[2 * buf.length];
        for (int i = 0; i < buf.length; ++i) {
            chars[2 * i] = HEX_CHARS[(buf[i] & 0xF0) >>> 4];
            chars[2 * i + 1] = HEX_CHARS[buf[i] & 0x0F];
        }
        String hex = new String(chars);
        System.out.println("hex = [" + hex + "]");
        return hex;
    }

    public static String sign(HashMap<String, String> map) {
        return sign(map, "");
    }

    public static String sign(HashMap<String, String> map, String key) {
        return sign(map, key);
    }

    private static String sign(Map<String, String> hashMap, String dvcCode, String encryptKey) {
        byte[] bytes;
        String createLinkString = createLinkString(hashMap);
        if (isEmpty(encryptKey)) {
            StringBuilder stringBuilder = new StringBuilder();
            stringBuilder.append(createLinkString);
            stringBuilder.append(dvcCode);
            createLinkString = stringBuilder.toString();
        } else {
            StringBuilder stringBuilder2 = new StringBuilder();
            stringBuilder2.append(createLinkString);
            stringBuilder2.append(encryptKey);
            createLinkString = stringBuilder2.toString();
        }
        byte[] bArr = new byte[0];
        try {
            bytes = MD5Util.MD5Encode(createLinkString).getBytes("GBK");
        } catch (Throwable e) {
            e.printStackTrace();
            bytes = bArr;
        }
        return Base64.encodeBase64String(bytes);
    }

    private static String createLinkString(Map<String, String> map) {
        List arrayList = new ArrayList(map.keySet());
        Collections.sort(arrayList);
        String str = "";
        for (int i = 0; i < arrayList.size(); i++) {
            String str2 = (String) arrayList.get(i);
            String str3 = (String) map.get(str2);
            StringBuilder stringBuilder;
            if (i == arrayList.size() - 1) {
                stringBuilder = new StringBuilder();
                stringBuilder.append(str);
                stringBuilder.append(str2);
                stringBuilder.append(EQUAL_SIGN);
                stringBuilder.append(str3);
                str = stringBuilder.toString();
            } else {
                stringBuilder = new StringBuilder();
                stringBuilder.append(str);
                stringBuilder.append(str2);
                stringBuilder.append(EQUAL_SIGN);
                stringBuilder.append(str3);
                stringBuilder.append(PARAMETERS_SEPARATOR);
                str = stringBuilder.toString();
            }
        }
        return str;
    }

    public static final String ENCODING_UTF_8 = "UTF-8";
    public static final String EQUAL_SIGN = "=";
    public static final String HTTP_DEFUALT_PROXY = "10.0.0.172";
    public static final String PARAMETERS_SEPARATOR = "&";
    public static final String PATHS_SEPARATOR = "/";
    public static final String URL_AND_PARA_SEPARATOR = "?";
    /* renamed from: a */
    private static final SimpleDateFormat f618a = new SimpleDateFormat("EEE, d MMM yyyy HH:mm:ss z", Locale.ENGLISH);

    public static boolean isEmpty(@Nullable CharSequence str) {
        return str == null || str.length() == 0;
    }

}
