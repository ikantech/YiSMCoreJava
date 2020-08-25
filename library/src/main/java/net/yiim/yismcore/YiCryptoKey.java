package net.yiim.yismcore;

import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;

import java.math.BigInteger;
import java.security.SecureRandom;

public class YiCryptoKey {
    private final Object locker = new Object();

    // 对称加密算法
    private byte[] symmetricKey = null;
    private byte[] ivBytes = null;

    // sm2
    private ECDomainParameters sm2DomainParameters = null;
    private BigInteger sm2D = null;
    private ECPoint sm2Q = null;
    private byte[] sm2UserId = null;

    // rsa
    private AsymmetricKeyParameter rsaPrivateParameter;
    private AsymmetricKeyParameter rsaPublicParameter;

    /**
     * 对称加密算法，初始化密钥
     * @param keyBytes 密钥数据
     * @param ivBytes 向量数据
     * @throws YiCryptoException 密钥非法时抛出
     */
    public void setupSymmetricKey(byte[] keyBytes, byte[] ivBytes) throws YiCryptoException {
        if(keyBytes == null || keyBytes.length < 1) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        synchronized (locker) {
            this.symmetricKey = keyBytes;
            this.ivBytes = ivBytes;
        }
    }

    /**
     * 对称加密算法，获取密钥
     * @return 对称密钥数据
     */
    public byte[] getSymmetricKey() {
        return symmetricKey;
    }

    /**
     * 对称加密算法，获取向量
     * @return 向量数据
     */
    public byte[] getIV() {
        return ivBytes;
    }

    boolean checkSM2PublicKeyFail() {
        return sm2DomainParameters == null || sm2Q == null;
    }

    boolean checkSM2PrivateKeyFail() {
        return sm2D == null || sm2DomainParameters == null;
    }

    private void setupSM2Parameters() throws YiCryptoException {
        if(sm2DomainParameters == null) {
            synchronized (locker) {
                if(sm2DomainParameters == null) {
                    BigInteger p = new BigInteger(1, Hex.decode("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF"));
                    BigInteger a = new BigInteger(1, Hex.decode("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC"));
                    BigInteger b = new BigInteger(1, Hex.decode("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93"));
                    BigInteger n = new BigInteger(1, Hex.decode("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"));
                    BigInteger h = BigInteger.valueOf(1);
                    ECCurve curve = new ECCurve.Fp(p, a, b, n, h);

                    ECPoint point = curve.decodePoint(Hex.decode("04"
                            + "32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7"
                            + "BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0"));
                    sm2DomainParameters = new ECDomainParameters(curve, point, n, h, null);
                }
            }
        }
    }

    /**
     * 非对称加密算法，初始化国密SM2私钥
     * @param keyBytes 32字节密钥数据
     * @throws YiCryptoException 密钥非法时抛出
     */
    public void setupSM2PrivateKey(byte[] keyBytes) throws YiCryptoException {
        if(keyBytes == null || keyBytes.length != 32) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        setupSM2Parameters();
        synchronized (locker) {
            sm2D = new BigInteger(1, keyBytes);
        }
    }

    CipherParameters getSM2PrivateParameters() throws YiCryptoException {
        if(sm2D == null || sm2DomainParameters == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        if(sm2UserId != null && sm2UserId.length > 0) {
            return new ParametersWithID(new ECPrivateKeyParameters(sm2D, sm2DomainParameters), sm2UserId);
        }else {
            return new ECPrivateKeyParameters(sm2D, sm2DomainParameters);
        }
    }

    /**
     * 非对称加密算法，获取国密SM2私钥分量
     * @return 32字节密钥数据
     * @throws YiCryptoException 密钥非法时抛出
     */
    public byte[] getSM2PrivateKey() throws YiCryptoException {
        if(sm2D == null || sm2DomainParameters == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        return BigIntegers.asUnsignedByteArray(32, sm2D);
    }

    /**
     * 非对称加密算法，初始化国密SM2公钥，支持压缩公钥及非压缩公钥
     * 非压缩公钥PC||x||y，其中PC=4
     * 压缩公钥yTilde||x
     * @param keyBytes SM2公钥
     * @throws YiCryptoException 密钥非法时抛出
     */
    public void setupSM2PublicKey(byte[] keyBytes) throws YiCryptoException {
        if(keyBytes == null || (keyBytes.length != 33 && keyBytes.length != 65)) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        byte firstByte = keyBytes[0];
        if(firstByte != 0x04 && firstByte != 0x03 && firstByte != 0x02) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        setupSM2Parameters();
        try {
            synchronized (locker) {
                sm2Q = sm2DomainParameters.getCurve().decodePoint(keyBytes);
            }
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    CipherParameters getSM2PublicKeyParameters() throws YiCryptoException {
        if(sm2Q == null || sm2DomainParameters == null) {
            if(sm2D != null) {
                // gen public key from private key.
                getSM2PublicKey(false);
            }else {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }
        if(sm2UserId != null && sm2UserId.length > 0) {
            return new ParametersWithID(new ECPublicKeyParameters(sm2Q, sm2DomainParameters), sm2UserId);
        }else {
            return new ECPublicKeyParameters(sm2Q, sm2DomainParameters);
        }
    }

    /**
     * 非对称加密算法，获取国密SM2公钥
     * 如果初始化过公钥，则直接从公钥中获取
     * 如果初始化过私钥，则由私钥生成公钥
     * @return 压缩公钥或非压缩公钥
     * @throws YiCryptoException 密钥非法时抛出
     */
    public byte[] getSM2PublicKey(boolean compressed) throws YiCryptoException {
        setupSM2Parameters();
        if(sm2Q != null) {
            return sm2Q.getEncoded(compressed);
        }
        // 从私钥中生成
        if(sm2D != null) {
            synchronized (locker) {
                if(sm2D != null) {
                    ECPoint g = sm2DomainParameters.getG();
                    sm2Q = g.multiply(sm2D);
                    return sm2Q.getEncoded(compressed);
                }
            }
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
    }

    public byte[] getSM2UserId() {
        return sm2UserId;
    }

    public void setSM2UserId(byte[] sm2UserId) {
        this.sm2UserId = sm2UserId;
    }

    public void setupRSAKeyFromPEM(String pemStr) throws YiCryptoException {
        if(pemStr == null || pemStr.length() < 1) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        try {
            pemStr = pemStr.replaceAll("\r*\n*$", "");
            pemStr = pemStr.replaceAll("\r*\n*", "");
            if(pemStr.startsWith("-----BEGIN RSA PRIVATE KEY-----") &&
                    pemStr.endsWith("-----END RSA PRIVATE KEY-----")) {
                // pkcs#1 private key
                pemStr = pemStr.replaceAll("^-----BEGIN RSA PRIVATE KEY-----\r*\n*", "");
                pemStr = pemStr.replaceAll("-----END RSA PRIVATE KEY-----\r*\n*$", "");
                setupRSAPrivateKeyFromPKCS1(YiBase64.fromBase64String(pemStr));
            }else if(pemStr.startsWith("-----BEGIN PRIVATE KEY-----") &&
                    pemStr.endsWith("-----END PRIVATE KEY-----")) {
                // pkcs#8 private key
                pemStr = pemStr.replaceAll("^-----BEGIN PRIVATE KEY-----\r*\n*", "");
                pemStr = pemStr.replaceAll("-----END PRIVATE KEY-----\r*\n*$", "");
                setupRSAPrivateKeyFromPKCS8(YiBase64.fromBase64String(pemStr));
            }else if(pemStr.startsWith("-----BEGIN RSA PUBLIC KEY-----") &&
                    pemStr.endsWith("-----END RSA PUBLIC KEY-----")) {
                // pkcs#1 public key
                pemStr = pemStr.replaceAll("^-----BEGIN RSA PUBLIC KEY-----\r*\n*", "");
                pemStr = pemStr.replaceAll("-----END RSA PUBLIC KEY-----\r*\n*$", "");
                setupRSAPublicKeyFromPKCS1(YiBase64.fromBase64String(pemStr));
            }else if(pemStr.startsWith("-----BEGIN PUBLIC KEY-----") &&
                    pemStr.endsWith("-----END PUBLIC KEY-----")) {
                // pkcs#8 public key
                pemStr = pemStr.replaceAll("^-----BEGIN PUBLIC KEY-----\r*\n*", "");
                pemStr = pemStr.replaceAll("-----END PUBLIC KEY-----\r*\n*$", "");
                setupRSAPublicKeyFromPKCS8(YiBase64.fromBase64String(pemStr));
            }else {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    private void pemWrite(StringBuilder sb, byte[] pemBytes) throws YiCryptoException {
        if(pemBytes == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        String pemBase64 = YiBase64.toBase64String(pemBytes);
        int len = pemBase64.length();
        while (len > 0) {
            int wlen = (len > 64) ? 64 : len;
            sb.append(pemBase64.substring(0, wlen));
            pemBase64 = pemBase64.substring(wlen);
            len -= wlen;
            sb.append('\n');
        }
    }

    public String getRSAPublicKeyToPem(boolean pkcs1) throws YiCryptoException {
        try {
            if (rsaPublicParameter instanceof RSAKeyParameters) {
                StringBuilder sb = new StringBuilder();
                byte[] pemBytes = null;
                if (pkcs1) {
                    sb.append("-----BEGIN RSA PUBLIC KEY-----\n");
                    RSAKeyParameters rsaKeyParameters = (RSAKeyParameters) rsaPublicParameter;
                    RSAPublicKey pkcs1PubK = new RSAPublicKey(rsaKeyParameters.getModulus(), rsaKeyParameters.getExponent());
                    ASN1Object pkcs1PubKObj = pkcs1PubK.toASN1Primitive();
                    pemBytes = pkcs1PubKObj.getEncoded();
                }else {
                    sb.append("-----BEGIN PUBLIC KEY-----\n");
                    SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.createSubjectPublicKeyInfo(rsaPublicParameter);
                    if(subjectPublicKeyInfo != null) {
                        ASN1Object asn1ObjectPublic = subjectPublicKeyInfo.toASN1Primitive();
                        pemBytes = asn1ObjectPublic.getEncoded();
                    }
                }
                pemWrite(sb, pemBytes);
                if(pkcs1) {
                    sb.append("-----END RSA PUBLIC KEY-----");
                }else {
                    sb.append("-----END PUBLIC KEY-----");
                }
                return sb.toString();
            }
        }catch (Exception ex) {
            // ignore
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
    }

    public String getRSAPrivateKeyToPem(boolean pkcs1) throws YiCryptoException {
        try {
            if (rsaPrivateParameter instanceof RSAKeyParameters) {
                StringBuilder sb = new StringBuilder();
                byte[] pemBytes;
                if (pkcs1) {
                    sb.append("-----BEGIN RSA PRIVATE KEY-----\n");
                    RSAPrivateCrtKeyParameters privKParams = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
                    RSAPrivateKey privK = new RSAPrivateKey(privKParams.getModulus(), privKParams.getPublicExponent(),
                            privKParams.getExponent(), privKParams.getP(), privKParams.getQ(),
                            privKParams.getDP(), privKParams.getDQ(), privKParams.getQInv());
                    ASN1Object privKObj = privK.toASN1Primitive();
                    pemBytes = privKObj.getEncoded();
                }else {
                    sb.append("-----BEGIN PRIVATE KEY-----\n");
                    PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(rsaPrivateParameter);
                    ASN1Object asn1ObjectPrivate = privateKeyInfo.toASN1Primitive();
                    pemBytes = asn1ObjectPrivate.getEncoded();
                }
                pemWrite(sb, pemBytes);
                if(pkcs1) {
                    sb.append("-----END RSA PRIVATE KEY-----");
                }else {
                    sb.append("-----END PRIVATE KEY-----");
                }
                return sb.toString();
            }
        }catch (Exception ex) {
            // ignore
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
    }

    private void setupRSAPrivateKeyFromPKCS1(byte[] pkcs1Bytes) throws YiCryptoException {
        try {
            if(pkcs1Bytes != null && pkcs1Bytes.length > 0) {
                RSAPrivateKey privK = RSAPrivateKey.getInstance(pkcs1Bytes);
                if (privK != null) {
                    rsaPrivateParameter = new RSAPrivateCrtKeyParameters(privK.getModulus(), privK.getPublicExponent(),
                            privK.getPrivateExponent(), privK.getPrime1(), privK.getPrime2(),
                            privK.getExponent1(), privK.getExponent2(), privK.getCoefficient());
                    rsaPublicParameter = new RSAKeyParameters(false, privK.getModulus(),
                            privK.getPublicExponent());
                    return;
                }
            }
        }catch (Exception ex) {
            // ignore
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
    }

    private void setupRSAPrivateKeyFromPKCS8(byte[] pkcs8Bytes) throws YiCryptoException {
        try {
            PrivateKeyInfo keyInfo = PrivateKeyInfo.getInstance(pkcs8Bytes);
            AlgorithmIdentifier algId = keyInfo.getPrivateKeyAlgorithm();
            ASN1ObjectIdentifier algOID = algId.getAlgorithm();

            if (algOID.equals(PKCSObjectIdentifiers.rsaEncryption)
                    || algOID.equals(PKCSObjectIdentifiers.id_RSASSA_PSS)
                    || algOID.equals(X509ObjectIdentifiers.id_ea_rsa))
            {
                RSAPrivateKey keyStructure = RSAPrivateKey.getInstance(keyInfo.parsePrivateKey());

                rsaPrivateParameter = new RSAPrivateCrtKeyParameters(keyStructure.getModulus(),
                        keyStructure.getPublicExponent(), keyStructure.getPrivateExponent(),
                        keyStructure.getPrime1(), keyStructure.getPrime2(), keyStructure.getExponent1(),
                        keyStructure.getExponent2(), keyStructure.getCoefficient());
                rsaPublicParameter = new RSAKeyParameters(false, keyStructure.getModulus(),
                        keyStructure.getPublicExponent());
                return;
            }
        }catch (Exception ex) {
            // ignore
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
    }

    private void setupRSAPublicKeyFromPKCS1(byte[] pkcs1Bytes) throws YiCryptoException {
        try {
            RSAPublicKey pkcs1PubK = RSAPublicKey.getInstance(pkcs1Bytes);

            if(pkcs1PubK != null) {
                rsaPublicParameter = new RSAKeyParameters(false, pkcs1PubK.getModulus(),
                        pkcs1PubK.getPublicExponent());
                return;
            }
        }catch (Exception ex) {
            // ignore
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
    }

    private void setupRSAPublicKeyFromPKCS8(byte[] pkcs8Bytes) throws YiCryptoException {
        try {
            rsaPublicParameter = PublicKeyFactory.createKey(pkcs8Bytes);
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    AsymmetricKeyParameter getRSAPrivateParameter() {
        return rsaPrivateParameter;
    }

    AsymmetricKeyParameter getRSAPublicParameter() {
        return rsaPublicParameter;
    }

    public void setupRSAPublicKeyFromRaw(byte[] nBytes, byte[] eBytes) throws YiCryptoException {
        if(nBytes == null || eBytes == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        try {
            BigInteger n = new BigInteger(1, nBytes);
            BigInteger e = new BigInteger(1, eBytes);
            rsaPublicParameter = new RSAKeyParameters(false, n, e);
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    public void setupRSAPrivateKeyFromRaw(byte[] nBytes, byte[] eBytes, byte[] dBytes,
                                          byte[] pBytes, byte[] qBytes) throws YiCryptoException {
        if(nBytes == null || eBytes == null || dBytes == null || pBytes == null || qBytes == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        try {
            BigInteger n = new BigInteger(1, nBytes);
            BigInteger e = new BigInteger(1, eBytes);
            BigInteger d = new BigInteger(1, dBytes);
            BigInteger p = new BigInteger(1, pBytes);
            BigInteger q = new BigInteger(1, qBytes);

            // modulus n = p * q
//            BigInteger sn = p.multiply(q);

            BigInteger p1 = p.subtract(BigInteger.ONE);
            BigInteger q1 = q.subtract(BigInteger.ONE);
//            BigInteger phi = p1.multiply(q1);

            // private exponent d is the inverse of e mod phi
//            BigInteger sd = e.modInverse(phi);

            // 1st prime exponent pe = d mod (p - 1)
            BigInteger dp = d.mod(p1);

            // 2nd prime exponent qe = d mod (q - 1)
            BigInteger dq = d.mod(q1);

            // crt coefficient coeff is the inverse of q mod p
            BigInteger qinv = q.modInverse(p);

            RSAPrivateKey privK = new RSAPrivateKey(n, e, d, p, q, dp, dq, qinv);
            rsaPrivateParameter = new RSAPrivateCrtKeyParameters(privK.getModulus(), privK.getPublicExponent(),
                    privK.getPrivateExponent(), privK.getPrime1(), privK.getPrime2(),
                    privK.getExponent1(), privK.getExponent2(), privK.getCoefficient());

            rsaPublicParameter = new RSAKeyParameters(false, n, e);
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
    }

    public byte[] getRSA_NBytes() {
        if(rsaPublicParameter instanceof RSAKeyParameters) {
            RSAKeyParameters parameters = (RSAKeyParameters) rsaPublicParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getModulus());
        }
        if(rsaPrivateParameter instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters parameters = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getModulus());
        }
        return null;
    }

    public byte[] getRSA_EBytes() {
        if(rsaPublicParameter instanceof RSAKeyParameters) {
            RSAKeyParameters parameters = (RSAKeyParameters) rsaPublicParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getExponent());
        }
        if(rsaPrivateParameter instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters parameters = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getPublicExponent());
        }
        return null;
    }

    public byte[] getRSA_DBytes() {
        if(rsaPrivateParameter instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters parameters = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getExponent());
        }
        return null;
    }

    public byte[] getRSA_PBytes() {
        if(rsaPrivateParameter instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters parameters = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getP());
        }
        return null;
    }

    public byte[] getRSA_QBytes() {
        if(rsaPrivateParameter instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters parameters = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getQ());
        }
        return null;
    }

    public byte[] getRSA_DPBytes() {
        if(rsaPrivateParameter instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters parameters = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getDP());
        }
        return null;
    }

    public byte[] getRSA_DQBytes() {
        if(rsaPrivateParameter instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters parameters = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getDQ());
        }
        return null;
    }

    public byte[] getRSA_QInvBytes() {
        if(rsaPrivateParameter instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters parameters = (RSAPrivateCrtKeyParameters) rsaPrivateParameter;
            return BigIntegers.asUnsignedByteArray(parameters.getQInv());
        }
        return null;
    }

    /**
     * 非对称加密算法，国密SM2密钥对生成
     * @return 返回生成的国密SM2密钥对
     * @throws YiCryptoException 计算错误时抛出
     */
    public static YiCryptoKey genSM2KeyPair() throws YiCryptoException {
        YiCryptoKey cryptoKey = new YiCryptoKey();
        cryptoKey.setupSM2Parameters();

        ECKeyPairGenerator keyPairGenerator = new ECKeyPairGenerator();
        keyPairGenerator.init(new ECKeyGenerationParameters(cryptoKey.sm2DomainParameters, new SecureRandom()));

        AsymmetricCipherKeyPair keyPair = keyPairGenerator.generateKeyPair();
        ECPrivateKeyParameters ecpriv = (ECPrivateKeyParameters) keyPair.getPrivate();
        ECPublicKeyParameters ecpub = (ECPublicKeyParameters) keyPair.getPublic();

        cryptoKey.sm2D = ecpriv.getD();
        cryptoKey.sm2Q = ecpub.getQ();

        return cryptoKey;
    }

    /**
     * 非对称加密算法，国际RSA密钥对生成
     * @param strength 密钥长度
     * @return 返回生成的RSA密钥对
     * @throws YiCryptoException 计算错误时抛出
     */
    public static YiCryptoKey genRSAKeyPair(int strength) throws YiCryptoException {
        return genRSAKeyPair(0x10001, strength);
    }

    /**
     * 非对称加密算法，国际RSA密钥对生成
     * @param publicExponent 公钥指数e
     * @param strength 密钥长度
     * @return 返回生成的RSA密钥对
     * @throws YiCryptoException 计算错误时抛出
     */
    public static YiCryptoKey genRSAKeyPair(int publicExponent, int strength) throws YiCryptoException {
        YiCryptoKey cryptoKey = new YiCryptoKey();

        RSAKeyPairGenerator rsaKeyPairGenerator = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters rsaKeyGenerationParameters = new RSAKeyGenerationParameters(
                BigInteger.valueOf(publicExponent), CryptoServicesRegistrar.getSecureRandom(), strength,
                getDefaultCertainty(strength));
        //初始化参数
        rsaKeyPairGenerator.init(rsaKeyGenerationParameters);

        AsymmetricCipherKeyPair keyPair = rsaKeyPairGenerator.generateKeyPair();

        //公钥
        cryptoKey.rsaPublicParameter = keyPair.getPublic();
        //私钥
        cryptoKey.rsaPrivateParameter = keyPair.getPrivate();

        return cryptoKey;
    }

    private static int getDefaultCertainty(int keySizeInBits)
    {
        // Based on FIPS 186-4 Table C.1
        return keySizeInBits <= 1024 ? 80 : (96 + 16 * ((keySizeInBits - 1) / 1024));
    }
}
