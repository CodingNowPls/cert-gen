import com.xiuye.cert.DcCertGenUtil;
import com.xiuye.cert.bean.KeyStoreInfo;
import com.xiuye.cert.bean.SignedCertInfo;
import com.xiuye.cert.util.CertUtil;
import org.junit.Test;

import java.util.Date;

/**
 * 数字证书验证
 */
public class DCGenTest {

    public static final String genBasePath = "E:\\workspace\\ideaCommunityProjects\\CertGen\\src\\main\\resources\\cert\\";

    public static final String CERT_NAME_JINGKE = "jingke.keystore";
    public static final String CERT_NAME_JINGKE_ALIAS = "荆轲";
    public static final String CERT_NAME_JINGKE_KEYSTORE_PASSWORD = "123";
    public static final String CERT_NAME_JINGKE_CERT_PASSWORD = "456";
    public static final String CERT_NAME_JINGKE_CERT_NAME = "jingke.cer";
    public static final String CERT_NAME_JINGKE_CHILD_CERT_NAME = "荆轲子证书_signed.cer";


    public static final String CERT_NAME_WUMING = "wuming.keystore";
    public static final String CERT_NAME_WUMING_ALIAS = "无名";
    public static final String CERT_NAME_WUMING_KEYSTORE_PASSWORD = "789";
    public static final String CERT_NAME_WUMING_CERT_PASSWORD = "101";
    public static final String CERT_NAME_WUMING_CERT_NAME = "wuming.cer";
    public static final String CERT_NAME_WUMING_CHILD_CERT_NAME = "无名子证书_signed.cer";
    public static final String CERT_NAME_WUMING_CHILD_CERT_ALIAS = "无名子证书";
    public static final String CERT_NAME_WUMING_CHILD_CERT_PASSWORD = "无名子证书";


    /**
     * 1. 生成证书库/证书
     */
    @Test
    public void testGenRootCert() {
        // 别名,库密码,证书密码,CN,OU,O,L,ST,C,开始时间,有效期限(单位:天),存储路径
        KeyStoreInfo certInfo = new KeyStoreInfo(CERT_NAME_JINGKE_ALIAS, CERT_NAME_JINGKE_KEYSTORE_PASSWORD, CERT_NAME_JINGKE_CERT_PASSWORD
                , CERT_NAME_JINGKE_ALIAS, "燕国", "燕国", "燕国", "辽宁", "CN", new Date(), 365,
                genBasePath + CERT_NAME_JINGKE);
        DcCertGenUtil.generateJKS(certInfo);

        certInfo = new KeyStoreInfo(CERT_NAME_WUMING_ALIAS, CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_CERT_PASSWORD
                , CERT_NAME_WUMING_ALIAS, "中国", "中国", "北京", "北京", "CN", new Date(), 365,
                genBasePath + CERT_NAME_WUMING);
        DcCertGenUtil.generateJKS(certInfo);

        certInfo = new KeyStoreInfo(CERT_NAME_WUMING_ALIAS, CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_CERT_PASSWORD
                , CERT_NAME_WUMING_ALIAS, "中国", "中国", "北京", "北京", "CN", new Date(), 365,
                genBasePath + CERT_NAME_WUMING);

        DcCertGenUtil.generateJKS(certInfo);
        System.out.println("testGenerateCert end");
    }

    /**
     * 2. 添加新证书到证书库
     */
    @Test
    public void testAddNewCert() {
        KeyStoreInfo certInfo = new KeyStoreInfo(
                "荆轲2号", CERT_NAME_JINGKE_KEYSTORE_PASSWORD, CERT_NAME_JINGKE_CERT_PASSWORD
                , "荆轲2号", "燕国", "燕国", "燕国", "辽宁", "CN", new Date(), 365,
                genBasePath + CERT_NAME_JINGKE);
        DcCertGenUtil.addNewCert2JKS(certInfo);

        certInfo = new KeyStoreInfo("无名3号", CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_CERT_PASSWORD
                , "无名3号", "中国", "中国", "北京", "北京", "CN", new Date(), 365
                , genBasePath + CERT_NAME_WUMING);
        DcCertGenUtil.addNewCert2JKS(certInfo);
        certInfo = new KeyStoreInfo("无名7", CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_CERT_PASSWORD
                , "无名4号", "中国", "中国", "北京", "北京", "CN", new Date(), 365
                , genBasePath + CERT_NAME_WUMING);
        DcCertGenUtil.addNewCert2JKS(certInfo);
        System.out.println("testAddNewCert end");
    }


    /**
     * 3.导出公钥证书cer
     */
    @Test
    public void testExportCert() {
        // 证书库路径,库密码,别名,cer证书路径
        DcCertGenUtil.exportJKSPublicKeyCertificate(genBasePath + CERT_NAME_WUMING
                , CERT_NAME_WUMING_KEYSTORE_PASSWORD, CERT_NAME_WUMING_ALIAS, genBasePath + CERT_NAME_WUMING_CERT_NAME);
        DcCertGenUtil.exportJKSPublicKeyCertificate(genBasePath + CERT_NAME_JINGKE
                , CERT_NAME_JINGKE_KEYSTORE_PASSWORD, CERT_NAME_JINGKE_ALIAS, genBasePath + CERT_NAME_JINGKE_CERT_NAME);
    }

    /**
     * 4.1根据根证书签发证书
     */
    @Test
    public void testGenChildSignCert() {
        // 签发证书的信息
        SignedCertInfo signedCertInfo = new SignedCertInfo();
        String s = "荆轲子证书";
        // 签发证书:C
        signedCertInfo.setCountry(s);
        // 签发证书:CN
        signedCertInfo.setName(s);
        // 证书颁发者别名
        signedCertInfo.setIssuerAlias(CERT_NAME_JINGKE_ALIAS);
        // 证书颁发者证书密码
        signedCertInfo.setIssuerAliasPwd(CERT_NAME_JINGKE_CERT_PASSWORD);
        // 颁发者的所在证书库
        signedCertInfo.setKeyStorePwd(CERT_NAME_JINGKE_KEYSTORE_PASSWORD);
        // 颁发者证书库路径
        signedCertInfo.setKeyStorePath(genBasePath + CERT_NAME_JINGKE);
        // 签发证书:L
        signedCertInfo.setLocation(s);
        // 签发证书:O
        signedCertInfo.setOrg(s);
        // 签发证书:OU
        signedCertInfo.setOrgUnit(s);
        // 签发证书:ST
        signedCertInfo.setProvince(s);
        // 使用者证书别名
        signedCertInfo.setSubjectAlias(s);
        // 使用者证书密码
        signedCertInfo.setSubjectAliasPwd(s);
        // 存储签发证书的路径
        signedCertInfo.setSubjectPath(genBasePath + CERT_NAME_JINGKE_CHILD_CERT_NAME);
        signedCertInfo.setValidity(365 * 2);// 有效期,单位:天
        System.out.println(signedCertInfo);
        // 签发证书("无名3子证书"的证书),并且存储到证书库("CurrentTest.keystore")
        DcCertGenUtil.signCertJKSForSubject(signedCertInfo);
    }
    /**
     * 4.2根据根证书签发证书
     */
    @Test
    public void testGenChildSignCert2() {
        // 签发证书的信息
        SignedCertInfo signedCertInfo = new SignedCertInfo();
        String s = "无名子证书";
        // 签发证书:C
        signedCertInfo.setCountry("CN");
        // 签发证书:CN
        signedCertInfo.setName(CERT_NAME_WUMING_CHILD_CERT_ALIAS);
        // 证书颁发者别名
        signedCertInfo.setIssuerAlias(CERT_NAME_WUMING_ALIAS);
        // 证书颁发者证书密码
        signedCertInfo.setIssuerAliasPwd(CERT_NAME_WUMING_CERT_PASSWORD);
        // 颁发者的所在证书库
        signedCertInfo.setKeyStorePwd(CERT_NAME_WUMING_KEYSTORE_PASSWORD);
        // 颁发者证书库路径
        signedCertInfo.setKeyStorePath(genBasePath + CERT_NAME_WUMING);
        // 签发证书:L
        signedCertInfo.setLocation("北京");
        // 签发证书:O
        signedCertInfo.setOrg(s);
        // 签发证书:OU
        signedCertInfo.setOrgUnit(s);
        // 签发证书:ST
        signedCertInfo.setProvince(s);
        // 使用者证书别名
        signedCertInfo.setSubjectAlias(CERT_NAME_WUMING_CHILD_CERT_ALIAS);
        // 使用者证书密码
        signedCertInfo.setSubjectAliasPwd(CERT_NAME_WUMING_CHILD_CERT_PASSWORD);
        // 存储签发证书的路径
        signedCertInfo.setSubjectPath(genBasePath + CERT_NAME_WUMING_CHILD_CERT_NAME);
        signedCertInfo.setValidity(365 * 2);// 有效期,单位:天
        System.out.println(signedCertInfo);

        // 签发证书("无名3子证书"的证书),并且存储到证书库("CurrentTest.keystore")
        DcCertGenUtil.signCertJKSForSubject(signedCertInfo);
    }

    @Test
    public void listAliases() {
        System.out.println("----------jingke------------------");
        System.out.println(CertUtil.allAliasesInJKS(genBasePath + CERT_NAME_JINGKE, CERT_NAME_JINGKE_KEYSTORE_PASSWORD));
        System.out.println("----------wuming------------------");
        System.out.println(CertUtil.allAliasesInJKS(genBasePath + CERT_NAME_WUMING, CERT_NAME_WUMING_KEYSTORE_PASSWORD));
    }

}
