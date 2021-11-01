package com.xiuye.cert.util;

import com.xiuye.cert.DcCertGenUtil;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.*;
import java.util.*;

/**
 * 证书工具类
 */
public class CertUtil {

    public static byte[] encodeByKeyStorePublicKey(KeyStore ks, String alias, byte[] input) {
        try {
            PublicKey pk = ks.getCertificate(alias).getPublicKey();
            return crypt(Cipher.ENCRYPT_MODE, pk, input);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;

    }

    public static byte[] decodeByKeyStorePublicKey(KeyStore ks, String alias, byte[] input) {
        try {
            PublicKey pk = ks.getCertificate(alias).getPublicKey();
            return crypt(Cipher.DECRYPT_MODE, pk, input);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;

    }

    public static byte[] decodeByKeyStorePrivateKey(KeyStore ks, String alias, String certPwd, byte[] input) {
        PrivateKey pk;
        try {
            pk = (PrivateKey) ks.getKey(alias, certPwd.toCharArray());
            return crypt(Cipher.DECRYPT_MODE, pk, input);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;

    }

    public static byte[] encodeByKeyStorePrivateKey(KeyStore ks, String alias, String certPwd, byte[] input) {
        PrivateKey pk;
        try {
            pk = (PrivateKey) ks.getKey(alias, certPwd.toCharArray());
            return crypt(Cipher.ENCRYPT_MODE, pk, input);
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;

    }

    public static byte[] encodeByJKSPublicKey(String storePath,String storePwd, String alias, byte[] msg) {
        return encodeByKeyStorePublicKey(storePath, storePwd,
                DcCertGenUtil.KEY_STORE_TYPE_JKS, alias, msg);
    }

    public static byte[] decodeByJKSPublicKey(String storePath, String storePwd, String alias, byte[] msg) {
        return decodeByKeyStorePublicKey(storePath, storePwd,
                DcCertGenUtil.KEY_STORE_TYPE_JKS, alias, msg);
    }

    public static byte[] decodeByPFXPublicKey(String storePath, String storePwd, String alias, byte[] msg) {
        return decodeByKeyStorePublicKey(storePath, storePwd,
                DcCertGenUtil.KEY_STORE_TYPE_PKCS12, alias, msg);
    }

    public static byte[] encodeByPFXPublicKey(String storePath,String storePwd, String alias, byte[] msg) {
        return encodeByKeyStorePublicKey(storePath, storePwd, DcCertGenUtil.KEY_STORE_TYPE_PKCS12, alias, msg);
    }

    public static byte[] encodeByJKSPrivateKey(String storePath, String storePwd, String alias, String certPwd, byte[] msg) {
        return encodeByKeyStorePrivateKey(storePath, storePwd,DcCertGenUtil.KEY_STORE_TYPE_JKS, alias, certPwd, msg);
    }

    public static byte[] decodeByJKSPrivateKey(String storePath, String storePwd, String alias, String certPwd, byte[] msg) {
        return decodeByKeyStorePrivateKey(storePath, storePwd,DcCertGenUtil.KEY_STORE_TYPE_JKS, alias,  certPwd, msg);
    }

    public static byte[] decodeByPFXPrivateKey(String storePath, String storePwd, String alias, String certPwd, byte[] msg) {
        return decodeByKeyStorePrivateKey(storePath, storePwd, DcCertGenUtil.KEY_STORE_TYPE_PKCS12, alias, certPwd, msg);
    }

    public static byte[] encodeByPFXPrivateKey(String storePath, String storePwd, String alias, String certPwd, byte[] msg) {
        return encodeByKeyStorePrivateKey(storePath, storePwd,
                DcCertGenUtil.KEY_STORE_TYPE_PKCS12, alias,
                certPwd, msg);
    }

    public static byte[] encodeByKeyStorePublicKey(String storePath, String storePwd, String storeType
                                                                                , String alias, byte[] msg) {
        PublicKey pk = publicKeyInKeyStore(storePath, storePwd, storeType, alias);
        return crypt(Cipher.ENCRYPT_MODE, pk, msg);
    }

    public static byte[] decodeByKeyStorePublicKey(String storePath, String storePwd , String storeType
                                                    , String alias, byte[] msg) {
        PublicKey pk = publicKeyInKeyStore(storePath, storePwd, storeType,  alias);
        return crypt(Cipher.DECRYPT_MODE, pk, msg);
    }

    public static byte[] encodeByKeyStorePrivateKey(String storePath,String storePwd
                                     , String storeType, String alias, String certPwd, byte[] msg) {

        PrivateKey pk = privateKeyInKeyStore(storePath, storePwd, storeType, alias, certPwd);
        return crypt(Cipher.ENCRYPT_MODE, pk, msg);

    }

    public static byte[] decodeByKeyStorePrivateKey(String storePath, String storePwd, String storeType
                                                             , String alias, String certPwd, byte[] msg) {
        PrivateKey pk = privateKeyInKeyStore(storePath, storePwd, storeType, alias, certPwd);
        return crypt(Cipher.DECRYPT_MODE, pk, msg);
    }

    private static byte[] crypt(int opmode, Key key, byte[] input) {
        Cipher cipher;
        try {
            cipher = Cipher.getInstance(DcCertGenUtil.KEY_PAIR_ALGORITHM_RSA);
            cipher.init(opmode, key);
            return cipher.doFinal(input);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;

    }

    public static byte[] decodeByCert(String certPath, byte[] msgData) {
        try {
            PublicKey pk = publicKeyInCert(certPath);
            Cipher cipher = Cipher.getInstance(DcCertGenUtil.KEY_PAIR_ALGORITHM_RSA);
            cipher.init(Cipher.DECRYPT_MODE, pk);
            byte[] data = cipher.doFinal(msgData);
            return data;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;

    }

    public static byte[] encodeByCert(String certPath, byte[] msgData) {
        try {
            PublicKey pk = publicKeyInCert(certPath);
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, pk);
            byte[] data = cipher.doFinal(msgData);
            return data;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PublicKey publicKeyInPFX(String storePath, String storePwd, String alias) {
        return publicKeyInKeyStore(storePath, storePwd,
                DcCertGenUtil.KEY_STORE_TYPE_PKCS12, alias);
    }

    public static PublicKey publicKeyInJKS(String storePath, String storePwd, String alias) {
        return publicKeyInKeyStore(storePath, storePwd,
                DcCertGenUtil.KEY_STORE_TYPE_JKS, alias);
    }

    public static PublicKey publicKeyInKeyStore(String storePath, String storePwd, String storeType, String alias) {
        KeyStore ks = keyStoreLoad(storePath, storePwd, storeType);
        try {
            return ks.getCertificate(alias).getPublicKey();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static PrivateKey privateKeyInJKS(String storePath, String storePwd, String alias, String certPwd) {
        return privateKeyInKeyStore(storePath, storePwd,
                DcCertGenUtil.KEY_STORE_TYPE_JKS, alias, certPwd);
    }

    public static PrivateKey privateKeyInPFX(String storePath, String storePwd, String alias, String certPwd) {
        return privateKeyInKeyStore(storePath, storePwd,
                DcCertGenUtil.KEY_STORE_TYPE_PKCS12, alias,
                certPwd);
    }

    public static PrivateKey privateKeyInKeyStore(String storePath, String storePwd, String storeType
                                                , String alias, String certPwd) {
        KeyStore ks = keyStoreLoad(storePath, storePwd, storeType);
        PrivateKey pk = null;
        try {
            pk = (PrivateKey) ks.getKey(alias, certPwd.toCharArray());
        } catch (UnrecoverableKeyException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return pk;
    }

    public static KeyStore keyStoreLoad(String storePath, String storePwd, String storeType) {
        try (FileInputStream fis = new FileInputStream(storePath)){
            KeyStore ks = KeyStore.getInstance(storeType);
            ks.load(fis, storePwd.toCharArray());
            return ks;
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {}
        return null;
    }

    public static PublicKey publicKeyInCert(String certPath) {
        return cert(certPath).getPublicKey();

    }

    public static List<String> allAliasesInJKS(String storePath, String storePwd) {
        return allAliasesInKeyStore(storePath,
                DcCertGenUtil.KEY_STORE_TYPE_JKS, storePwd);
    }

    public static List<String> allAliasesInPFX(String storePath, String storePwd) {
        return allAliasesInKeyStore(storePath,
                DcCertGenUtil.KEY_STORE_TYPE_PKCS12, storePwd);
    }

    public static List<String> allAliasesInKeyStore(String storePath, String keyStoreType, String storePwd) {
        List<String> aliases = new ArrayList<String>();
        File file = new File(storePath);
        KeyStore outStore;
        try (FileInputStream fis = new FileInputStream(file)){
            outStore = KeyStore.getInstance(keyStoreType);
            outStore.load(fis, storePwd.toCharArray());
            Enumeration<String> e = outStore.aliases();
            while (e.hasMoreElements()) {
                String alias = e.nextElement();
                aliases.add(alias);
            }
        } catch (KeyStoreException e1) {
            e1.printStackTrace();
        } catch (FileNotFoundException e1) {
            e1.printStackTrace();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (CertificateException e1) {
            e1.printStackTrace();
        } catch (IOException e1) {
            e1.printStackTrace();
        } finally {}
        return aliases;

    }

    public static void verifyValidityDays(String certPath) {
        X509Certificate cert = (X509Certificate) cert(certPath);
        try {
            cert.checkValidity(new Date());
        } catch (CertificateExpiredException e) {
            e.printStackTrace();
        } catch (CertificateNotYetValidException e) {
            e.printStackTrace();
        }
    }

    public static void verifySign(String fatherCertPath, String sonCertPath) {
        Certificate son = cert(sonCertPath);
        Certificate father = cert(fatherCertPath);
        try {
            son.verify(father.getPublicKey());
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }

    }

    public static Certificate cert(String certPath) {
        try (FileInputStream fis = new FileInputStream(certPath)){
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            return cf.generateCertificate(fis);
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

}
