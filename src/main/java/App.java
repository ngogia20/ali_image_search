import org.apache.commons.codec.binary.Base64;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import sun.misc.BASE64Encoder;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.SimpleDateFormat;
import java.util.*;


public class App {
    private final static String CHARSET_UTF8 = "utf8";
    private final static String ALGORITHM = "UTF-8";
    private final static int MAX_POST_CONTENT_LENGTH = 8 * 1024 * 1024;

    // user need specefied



    // Nikesh Image Search
    private static String keySecrect = "";
    private static String accessKeyId = "";
    private static String instanceName = "";


    // for shanghai
    private static String domain = "imagesearch.ap-southeast-1.aliyuncs.com";
    // for singapore
    // private static String domain = "imagesearch.ap-southeast-1.aliyuncs.com";

    public static String buildSearchContent(String picName, String category) {
        String filePath = "/Users/nikeshgogia/IdeaProjects/ImageSearchAPI/src/main/resources/" + picName;
        byte[] fileBytes = getFileBytes(filePath);

        Map<String, String> kv = new HashMap<String, String>();
        kv.put("s", String.valueOf(0));
        kv.put("n", String.valueOf(10));
        if (category != null && category.length() > 0) {
            kv.put("cat_id", category);
        }

        Base64 base64 = new Base64();
        String encodePicName = base64.encodeToString("searchPic".getBytes());
        String encodePicContent = base64.encodeToString(fileBytes);

        kv.put("pic_list", encodePicName);
        kv.put(encodePicName, encodePicContent);

        String content = buildContent(kv);
        if (content.length() > MAX_POST_CONTENT_LENGTH) {
            return null;
        }

        return content;
    }

    public static String buildDeleteContent(String itemId) {
        Map<String, String> kv = new HashMap<String, String>();
        kv.put("item_id", itemId);

        String content = buildContent(kv);
        if (content.length() > MAX_POST_CONTENT_LENGTH) {
            return null;
        }

        return content;
    }

    public static String buildAddContent(String itemId, String picName, String category) {
        Map<String, String> kv = new HashMap<String, String>();

        kv.put("item_id", itemId);
        kv.put("cat_id", category);

        String custContent = "{\"100\":\"T-shirts Mens Red Strip Collar T-Shirt\"}";

        kv.put("cust_content", custContent);

        String filePath = "/Users/nikeshgogia/IdeaProjects/ImageSearchAPI/src/main/resources/" + picName;

        byte[] fileBytes = getFileBytes(filePath);

        Map<String, String> picMap = new HashMap<String, String>();
        Base64 base64 = new Base64();
        String encodePicName = base64.encodeToString(picName.getBytes());
        String encodePicContent = base64.encodeToString(fileBytes);
        picMap.put(encodePicName, encodePicContent);

        StringBuilder builder = new StringBuilder();
        for (Map.Entry<String, String> entry : picMap.entrySet()) {
            builder.append(entry.getKey());
            builder.append(",");
            kv.put(entry.getKey(), entry.getValue());
        }

        String picListStr = builder.toString();
        kv.put("pic_list", picListStr.substring(0, picListStr.length() - 1));

        String content = buildContent(kv);
        if (content.length() > MAX_POST_CONTENT_LENGTH) {
            return null;
        }

        return content;
    }

    private static String buildContent(Map<String, String> kv) {
        String meta = "";
        String body = "";
        int start = 0;
        for (Map.Entry<String, String> entry : kv.entrySet()) {
            String value = entry.getValue();
            if (meta.length() > 0) {
                meta += "#";
            }
            meta += entry.getKey() + "," + String.valueOf(start) + "," + String.valueOf(start + value.length());
            body += value;
            start += value.length();
        }
        return meta + "^" + body;
    }

    private static String getMd5(String body) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        BASE64Encoder base64en = new BASE64Encoder();
        //加密后的字符串
        return base64en.encode(md5.digest(body.getBytes("utf-8")));
    }

    private static String getGMT() {
        Calendar cd = Calendar.getInstance();
        SimpleDateFormat sdf = new SimpleDateFormat("EEE d MMM yyyy HH:mm:ss 'GMT'", Locale.US);
        sdf.setTimeZone(TimeZone.getTimeZone("GMT")); // 设置时区为GMT
        return sdf.format(cd.getTime());
    }


    private static String generateSignatureNonce() {
        String base = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < 32; i++) {
            int number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }

    public static String buildSignatureStr(String instanceName, String operation, String postContent, Map<String, String> headers) {
        String data = "POST\n";
        String accept = "application/json";
        data += accept + "\n";

        String contentMd5 = null;
        try {
            contentMd5 = getMd5(postContent);
        } catch (NoSuchAlgorithmException e) {
            return null;
        } catch (UnsupportedEncodingException e) {
            return null;
        }
        data += contentMd5 + "\n";

        String contentType = "application/octet-stream;charset=utf-8";
        data += contentType + "\n";

        String gmt = getGMT();
        data += gmt + "\n";

        String method = "HMAC-SHA1";
        data += "x-acs-signature-method:" + method + "\n";

        String signatureNonce = generateSignatureNonce();
        data += "x-acs-signature-nonce:" + signatureNonce + "\n";

        String apiVersion = "2018-01-20";
        data += "x-acs-version:" + apiVersion + "\n";
        data += "/item/" + operation + "?instanceName=" + instanceName;

        headers.put("x-acs-version", apiVersion);
        headers.put("x-acs-signature-method", method);
        headers.put("x-acs-signature-nonce", signatureNonce);

        headers.put("accept", accept);
        headers.put("content-md5", contentMd5);
        headers.put("content-type", contentType);
        headers.put("date", gmt);

        return data;
    }

    private static byte[] hmacSHA1Signature(String secret, String baseString) throws Exception {
        if (secret == null || secret.length() == 0) {
            throw new IOException("secret can not be empty");
        }
        if (baseString == null || baseString.length() == 0) {
            return null;
        }
        Mac mac = Mac.getInstance("HmacSHA1");
        SecretKeySpec keySpec = new SecretKeySpec(secret.getBytes(CHARSET_UTF8), ALGORITHM);
        mac.init(keySpec);
        return mac.doFinal(baseString.getBytes(CHARSET_UTF8));
    }

    public static String newStringByBase64(byte[] bytes)
            throws UnsupportedEncodingException {
        if (bytes == null || bytes.length == 0) {
            return null;
        }
        return new String(org.apache.commons.codec.binary.Base64.encodeBase64(bytes, false), CHARSET_UTF8);
    }

    private static byte[] getFileBytes(String filePath) {
        byte[] buffer = null;
        try {
            File file = new File(filePath);
            FileInputStream fis = new FileInputStream(file);
            ByteArrayOutputStream bos = new ByteArrayOutputStream(1024 * 1024);
            byte[] b = new byte[1000];
            int n;
            while ((n = fis.read(b)) != -1) {
                bos.write(b, 0, n);
            }
            fis.close();
            bos.close();
            buffer = bos.toByteArray();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return buffer;
    }

    public static String access(HttpRequestBase httpRequest) {
        CloseableHttpClient client = HttpClients.createDefault();
        HttpResponse response = null;
        String result = null;
        try {
            httpRequest.setHeader("accept-encoding", "");
            response = client.execute(httpRequest);
            if (response.getStatusLine().getStatusCode() == 200) {
                HttpEntity httpEntity = response.getEntity();
                result = EntityUtils.toString(httpEntity);
            } else {
                System.out.println(response.getStatusLine().getStatusCode());
            }
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }

        return result;
    }

    private static void testAddImage() throws Exception {
        String picName = "test2.JPG";
        String category = "0";
        String itemId = "100";

        System.out.println("With FC Shiv Patik");

        String postContent = buildAddContent(itemId, picName, category);

        System.out.println(postContent);

        Map<String, String> headers = new HashMap<String, String>();
        String signatureStr = buildSignatureStr(instanceName, "add", postContent, headers);
        System.out.println(signatureStr);

        byte[] signBytes = hmacSHA1Signature(keySecrect, signatureStr);
        String signature = newStringByBase64(signBytes);
        String authorization = "acs " + accessKeyId + ":" + signature;
        headers.put("authorization", authorization);
        System.out.println(authorization);

        String url = "http://" + domain + "/item/add?instanceName=" + instanceName;
        HttpPost httpPost = new HttpPost(url);
        for (String key : headers.keySet()) {
            httpPost.addHeader(key, headers.get(key));
        }

        httpPost.setEntity(new ByteArrayEntity(postContent.getBytes()));
        String result = access(httpPost);
        System.out.println(result);
    }

    private static void testSearchImage() throws Exception {
        // Dog Image String picName = "dog.jpeg";
        String picName = "first_cry_2.jpg";
        String category = "";

        String postContent = buildSearchContent(picName, category);

        Map<String, String> headers = new HashMap<String, String>();
        String signatureStr = buildSignatureStr(instanceName, "search", postContent, headers);
        System.out.println(signatureStr);

        byte[] signBytes = hmacSHA1Signature(keySecrect, signatureStr);
        String signature = newStringByBase64(signBytes);
        String authorization = "acs " + accessKeyId + ":" + signature;
        headers.put("authorization", authorization);
        System.out.println(authorization);

        String url = "http://" + domain + "/item/search?instanceName=" + instanceName;
        HttpPost httpPost = new HttpPost(url);
        for (String key : headers.keySet()) {
            httpPost.addHeader(key, headers.get(key));
        }

        httpPost.setEntity(new ByteArrayEntity(postContent.getBytes()));
        String result = access(httpPost);
        System.out.println(result);
    }

    private static void testDeleteImage() throws Exception {
        String itemId = "11111111";
        String postContent = buildDeleteContent(itemId);

        Map<String, String> headers = new HashMap<String, String>();
        String signatureStr = buildSignatureStr(instanceName, "delete", postContent, headers);
        System.out.println(signatureStr);

        byte[] signBytes = hmacSHA1Signature(keySecrect, signatureStr);
        String signature = newStringByBase64(signBytes);
        String authorization = "acs " + accessKeyId + ":" + signature;
        headers.put("authorization", authorization);
        System.out.println(authorization);

        String url = "http://" + domain + "/item/delete?instanceName=" + instanceName;
        HttpPost httpPost = new HttpPost(url);
        for (String key : headers.keySet()) {
            httpPost.addHeader(key, headers.get(key));
        }

        httpPost.setEntity(new ByteArrayEntity(postContent.getBytes()));
        String result = access(httpPost);
        System.out.println(result);
    }

    public static void main(String[] args) throws Exception {
        if (accessKeyId.length() == 0 || keySecrect.length() == 0 || instanceName.length() == 0) {
            System.err.println("accessKeyId accessKeySecret and instanceName need specify.");
            return;
        }

        //testAddImage();
        testSearchImage();
        //testDeleteImage();
    }
}

