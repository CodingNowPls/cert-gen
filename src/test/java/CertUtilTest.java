import com.xiuye.cert.util.CertUtil;
import org.junit.Test;

import java.security.PrivateKey;

public class CertUtilTest {

    private static final String basePath = DCGenTest.genBasePath;

    public static final String CERT_NAME_JINGKE = DCGenTest.CERT_NAME_JINGKE;
    public static final String CERT_NAME_JINGKE_ALIAS = DCGenTest.CERT_NAME_JINGKE_ALIAS;
    public static final String CERT_NAME_JINGKE_KEYSTORE_PASSWORD = DCGenTest.CERT_NAME_JINGKE_KEYSTORE_PASSWORD;
    public static final String CERT_NAME_JINGKE_CERT_PASSWORD = DCGenTest.CERT_NAME_JINGKE_CERT_PASSWORD;
    public static final String CERT_NAME_JINGKE_CERT_NAME = DCGenTest.CERT_NAME_JINGKE_CERT_NAME;
    public static final String CERT_NAME_JINGKE_CHILD_CERT_NAME = DCGenTest.CERT_NAME_JINGKE_CHILD_CERT_NAME;


    public static final String CERT_NAME_WUMING = DCGenTest.CERT_NAME_WUMING;
    public static final String CERT_NAME_WUMING_ALIAS = DCGenTest.CERT_NAME_WUMING_ALIAS;
    public static final String CERT_NAME_WUMING_KEYSTORE_PASSWORD =  DCGenTest.CERT_NAME_WUMING_KEYSTORE_PASSWORD;
    public static final String CERT_NAME_WUMING_CERT_PASSWORD = DCGenTest.CERT_NAME_WUMING_CERT_PASSWORD;
    public static final String CERT_NAME_WUMING_CERT_NAME = DCGenTest.CERT_NAME_WUMING_CERT_NAME;
    public static final String CERT_NAME_WUMING_CHILD_CERT_NAME = DCGenTest.CERT_NAME_WUMING_CHILD_CERT_NAME;
    public static final String CERT_NAME_WUMING_CHILD_CERT_ALIAS = DCGenTest.CERT_NAME_WUMING_CHILD_CERT_ALIAS;
    public static final String CERT_NAME_WUMING_CHILD_CERT_PASSWORD = DCGenTest.CERT_NAME_WUMING_CHILD_CERT_PASSWORD;


    /**
     *1. 验证签发证书的签名
     */
    @Test
    public void testCertVerify() {
        // "wuming3.cer"是根证书导出的公钥证书,"无名3子证书_signed.cer"是签发的子证书.
        CertUtil.verifySign(basePath + CERT_NAME_WUMING_CERT_NAME, basePath + CERT_NAME_WUMING_CHILD_CERT_NAME);
        CertUtil.verifySign(basePath + CERT_NAME_WUMING_CERT_NAME, basePath + CERT_NAME_WUMING_CERT_NAME);
        System.out.println("test passed!");
    }

    /**
     * 2.验证有效期,即证书没有过期,到当前时间有效.
     */
    @Test
    public void testCertValidityDays() {
        CertUtil.verifyValidityDays(basePath + CERT_NAME_WUMING_CERT_NAME);
        System.out.println("test passed!");
    }

    /**
     * 3.获取证书库中所有证书别名
     */
    @Test
    public void testGetAllAliasesInfo() {
        System.out.println(CertUtil.allAliasesInJKS(basePath + CERT_NAME_JINGKE,
                CERT_NAME_JINGKE_KEYSTORE_PASSWORD));
        System.out.println(CertUtil.allAliasesInJKS(basePath + CERT_NAME_WUMING, CERT_NAME_WUMING_KEYSTORE_PASSWORD));

    }

    /**
     * 4.获取cer证书的公钥
     */
    @Test
    public void testPublicKeyInCert() {
        System.out.println("---------------------wuming----------------");
        System.out.println(CertUtil.publicKeyInCert(basePath + CERT_NAME_WUMING_CERT_NAME));
        System.out.println("1 := "  + CertUtil.publicKeyInJKS(basePath + CERT_NAME_WUMING ,
                CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_ALIAS));
        System.out.println("---------------------jingke----------------");
        System.out.println(CertUtil.publicKeyInCert(basePath + CERT_NAME_JINGKE_CERT_NAME));
        System.out.println("2 := " + CertUtil.publicKeyInJKS(basePath + CERT_NAME_JINGKE, CERT_NAME_JINGKE_KEYSTORE_PASSWORD, CERT_NAME_JINGKE_ALIAS));

    }

    /**
     * 5.根据证书别名,获取证书库中该证书的私钥
     */
    @Test
    public void testPrivateKey() {
        // 证书库路径,证书库密码,证书别名,证书密码
        //
        PrivateKey privateKey_wuming = CertUtil.privateKeyInJKS(basePath + CERT_NAME_WUMING,
                CERT_NAME_WUMING_KEYSTORE_PASSWORD,  CERT_NAME_WUMING_ALIAS, CERT_NAME_WUMING_CERT_PASSWORD);
        System.out.println(privateKey_wuming.getAlgorithm());
        System.out.println(privateKey_wuming.getFormat());
        //jks
        PrivateKey privateKey_jingke = CertUtil.privateKeyInJKS(basePath + CERT_NAME_JINGKE, CERT_NAME_JINGKE_KEYSTORE_PASSWORD,
                CERT_NAME_JINGKE_ALIAS, CERT_NAME_JINGKE_CERT_PASSWORD);
        System.out.println(privateKey_jingke.getAlgorithm());
        System.out.println(privateKey_jingke.getFormat());

    }




    /**
     * 6.根据证书库中的证书(私钥公钥),加密解密
     */
    @Test
    public void testKeyStoreEncodeAndDecode() {
        String msg = "你好啊,奔跑者!";
        // 用私钥加密
        System.out.println("-----------------------------------------私钥加密--------------------------------");
        byte[] data = CertUtil.encodeByJKSPrivateKey(basePath + CERT_NAME_WUMING,
                CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_ALIAS, CERT_NAME_WUMING_CERT_PASSWORD, msg.getBytes());
        System.out.println(new String(data));
        // 用公钥解密
        System.out.println("-------------------------------------公钥解密--------------------------------------");
        data = CertUtil.decodeByJKSPublicKey(basePath + CERT_NAME_WUMING, CERT_NAME_WUMING_KEYSTORE_PASSWORD,
                CERT_NAME_WUMING_ALIAS, data);
        System.out.println(new String(data));

        System.out.println("==================================第二种=========================================");
        System.out.println("-----------------------------------------公钥加密--------------------------------");
        data = CertUtil.encodeByJKSPublicKey(basePath + CERT_NAME_WUMING, CERT_NAME_WUMING_KEYSTORE_PASSWORD,
                CERT_NAME_WUMING_ALIAS, msg.getBytes());
        System.out.println(new String(data));
        System.out.println("-----------------------------------------私钥解密--------------------------------");
        data = CertUtil.decodeByJKSPrivateKey(basePath + CERT_NAME_WUMING, CERT_NAME_WUMING_KEYSTORE_PASSWORD,
                CERT_NAME_WUMING_ALIAS, CERT_NAME_WUMING_CERT_PASSWORD, data);
        System.out.println(new String(data));

    }

    /**
     * 7.公钥证书cer的加密解密
     */
    @Test
    public void testCerFileEncodeAndDecode() {
        System.out.println("===========cer 证书加密==================");
        //[无名3号, 无名3子证书, 无名7, 无名2号]
        String msg = "[无名3号, 无名3子证书, 无名7, 无名2号]";
        // cer证书加密
        byte[] encodeBytes = CertUtil.encodeByCert(basePath + CERT_NAME_WUMING_CHILD_CERT_NAME, msg.getBytes());
        System.out.println(new String(encodeBytes));
        // 用其相关的私钥解密
        System.out.println("===========keystore 解密==================");
        byte[] decodeBytes = CertUtil.decodeByJKSPrivateKey(
                basePath + CERT_NAME_WUMING, CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_CHILD_CERT_ALIAS, CERT_NAME_WUMING_CHILD_CERT_PASSWORD, encodeBytes);
        System.out.println(new String(decodeBytes));

        System.out.println("============keystore 加密=================");
        // 用其相关的私钥加密
        byte[] encodeBytes2 = CertUtil.encodeByJKSPrivateKey(basePath + CERT_NAME_WUMING,
                CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_CHILD_CERT_ALIAS, CERT_NAME_WUMING_CHILD_CERT_PASSWORD, msg.getBytes());
        System.out.println(new String(encodeBytes2));
        // cer证书解密
        System.out.println("===========cer 证书解密==================");
        byte[]   decodeBytes2 = CertUtil.decodeByCert(basePath + CERT_NAME_WUMING_CHILD_CERT_NAME, encodeBytes2);
        System.out.println(new String(decodeBytes2));

    }

}
