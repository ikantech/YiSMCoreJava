package net.yiim.yismcore;

/**
 * Created by ikantech on 19-9-2.
 */
public class YiSMCore {
    private static final int TYPE_DIGEST = 0x01;
    private static final int TYPE_CIPHER = 0x02;
    private static final int TYPE_SIGNER = 0x04;

    enum Algorithm {
        UNKNOWN(-1, "no such algorithm"),

        // digest, 摘要算法
        // MD5 output 16bytes, 128bitLength
        MD5(1, "MD5"),
        // SHA1 output 20bytes, 160bitLength
        SHA1(2, "SHA1"),
        // SHA224 output 28bytes, 224bitLength
        SHA224(3, "SHA224"),
        // SHA256 output 32bytes, 256bitLength
        SHA256(4, "SHA256"),
        // SHA384 output 48bytes, 384bitLength
        SHA384(5, "SHA384"),
        // SHA512 output 64bytes, 512bitLength
        SHA512(6, "SHA512"),
        // SM3 output 32bytes, 256bitLength
        SM3(7, "SM3"),
        // SHA3-224 output 28bytes, 224bitLength
        SHA3_224(8, "SHA3-224"),
        // SHA3-256 output 32bytes, 256bitLength
        SHA3_256(9, "SHA3-256"),
        // SHA3-384 output 48bytes, 384bitLength
        SHA3_384(10, "SHA3-384"),
        // SHA3-512 output 64bytes, 512bitLength
        SHA3_512(11, "SHA3-512"),
        // BLAKE-2S output 32bytes, 256bitLength
        BLAKE_2S(12, "BLAKE-2S"),
        // BLAKE-2B output 64bytes, 512bitLength
        BLAKE_2B(13, "BLAKE-2B"),

        // rsa
        MD5WITHRSA(16, "MD5WithRSA"),
        SHA1WITHRSA(17, "SHA1WithRSA"),
        SHA224WITHRSA(18, "SHA224WithRSA"),
        SHA256WITHRSA(19, "SHA256WithRSA"),
        SHA384WITHRSA(20, "SHA384WithRSA"),
        SHA512WITHRSA(21, "SHA512WithRSA"),
        SHA3_224WITHRSA(22, "SHA3-224WithRSA"),
        SHA3_256WITHRSA(23, "SHA3-256WithRSA"),
        SHA3_384WITHRSA(24, "SHA3-384WithRSA"),
        SHA3_512WITHRSA(25, "SHA3-512WithRSA"),

        // rsa-pss
        MD5WITHRSA_PSS(30, "MD5WithRSA/PSS"),
        SHA1WITHRSA_PSS(31, "SHA1WithRSA/PSS"),
        SHA224WITHRSA_PSS(32, "SHA224WithRSA/PSS"),
        SHA256WITHRSA_PSS(33, "SHA256WithRSA/PSS"),
        SHA384WITHRSA_PSS(34, "SHA384WithRSA/PSS"),
        SHA512WITHRSA_PSS(35, "SHA512WithRSA/PSS"),
        SHA3_224WITHRSA_PSS(36, "SHA3-224WithRSA/PSS"),
        SHA3_256WITHRSA_PSS(37, "SHA3-256WithRSA/PSS"),
        SHA3_384WITHRSA_PSS(38, "SHA3-384WithRSA/PSS"),
        SHA3_512WITHRSA_PSS(39, "SHA3-512WithRSA/PSS"),

        // rsa-enc
        RSA_NOPADDING(44, "RSA/None/NoPadding"),
        RSA_PKCS1PADDING(45, "RSA/None/PKCS1Padding"),
        RSA_OAEPWITHMD5_MGF1PADDING(46, "RSA/None/OAEPWithMD5AndMGF1Padding"),
        RSA_OAEPWITHSHA1_MGF1PADDING(47, "RSA/None/OAEPWithSHA1AndMGF1Padding"),
        RSA_OAEPWITHSHA224_MGF1PADDING(48, "RSA/None/OAEPWithSHA224AndMGF1Padding"),
        RSA_OAEPWITHSHA256_MGF1PADDING(49, "RSA/None/OAEPWithSHA256AndMGF1Padding"),
        RSA_OAEPWITHSHA384_MGF1PADDING(50, "RSA/None/OAEPWithSHA384AndMGF1Padding"),
        RSA_OAEPWITHSHA512_MGF1PADDING(51, "RSA/None/OAEPWithSHA512AndMGF1Padding"),
        RSA_OAEPWITHSHA3_224_MGF1PADDING(52, "RSA/None/OAEPWithSHA3-224AndMGF1Padding"),
        RSA_OAEPWITHSHA3_256_MGF1PADDING(53, "RSA/None/OAEPWithSHA3-256AndMGF1Padding"),
        RSA_OAEPWITHSHA3_384_MGF1PADDING(54, "RSA/None/OAEPWithSHA3-384AndMGF1Padding"),
        RSA_OAEPWITHSHA3_512_MGF1PADDING(55, "RSA/None/OAEPWithSHA3-512AndMGF1Padding"),
        RSA_OAEPWITHBLAKE_2S_MGF1PADDING(56, "RSA/None/OAEPWithBLAKE-2SAndMGF1Padding"),
        RSA_OAEPWITHBLAKE_2B_MGF1PADDING(57, "RSA/None/OAEPWithBLAKE-2BAndMGF1Padding"),
        RSA_OAEPWITHSM3_MGF1PADDING(58, "RSA/None/OAEPWithSM3AndMGF1Padding"),

        // SM2 签名及验签算法
        BLAKE_2SWITHSM2(60, "BLAKE-2SWithSM2"),
        SHA3_256WITHSM2(61, "SHA3-256WithSM2"),
        SHA256WITHSM2(62, "SHA256WithSM2"),
        SM3WITHSM2(63, "SM3WithSM2"),

        // 非对称加密算法，国密SM2加密算法，其中摘要算法暂提供SM3及SHA256，输出支持两种模式
        // SM2 with SM3 or SHA256
        SM2WITHSM3_C1C2C3(64, "SM2WithSM3/C1C2C3"),
        SM2WITHSM3_C1C3C2(65, "SM2WithSM3/C1C3C2"),
        SM2WITHSHA256_C1C2C3(66, "SM2WithSHA256/C1C2C3"),
        SM2WITHSHA256_C1C3C2(67, "SM2WithSHA256/C1C3C2"),
        SM2WITHSHA3_256_C1C2C3(68, "SM2WithSHA3-256/C1C2C3"),
        SM2WITHSHA3_256_C1C3C2(69, "SM2WithSHA3-256/C1C3C2"),
        SM2WITHBLAKE_2S_C1C2C3(70, "SM2WithBLAKE-2S/C1C2C3"),
        SM2WITHBLAKE_2S_C1C3C2(71, "SM2WithBLAKE-2S/C1C3C2"),

        // HMAC
        HMAC_MD5(75, "HmacMD5"),
        HMAC_SHA1(76, "HmacSHA1"),
        HMAC_SHA224(77, "HmacSHA224"),
        HMAC_SHA256(78, "HmacSHA256"),
        HMAC_SHA384(79, "HmacSHA384"),
        HMAC_SHA512(80, "HmacSHA512"),
        HMAC_SHA3_224(81, "HmacSHA3-224"),
        HMAC_SHA3_256(82, "HmacSHA3-256"),
        HMAC_SHA3_384(83, "HmacSHA3-384"),
        HMAC_SHA3_512(84, "HmacSHA3-512"),
        HMAC_SM3(85, "HmacSM3"),
        HMAC_BLAKE_2S(86, "HmacBLAKE-2S"),
        HMAC_BLAKE_2B(87, "HmacBLAKE-2B"),

        // 对称加密算法
        // AES, key length 128/192/256 bits, block size 16bytes
        AES_ECB_NOPADDING(90, "AES/ECB/NoPadding"),
        AES_CBC_NOPADDING(91, "AES/CBC/NoPadding"),
        AES_ECB_PKCS7PADDING(92, "AES/ECB/PKCS7Padding"),
        AES_CBC_PKCS7PADDING(93, "AES/CBC/PKCS7Padding"),

        // DES, key length 64 bits, block size 8bytes
        DES_ECB_NOPADDING(94, "DES/ECB/NoPadding"),
        DES_CBC_NOPADDING(95, "DES/CBC/NoPadding"),
        DES_ECB_PKCS7PADDING(96, "DES/ECB/PKCS7Padding"),
        DES_CBC_PKCS7PADDING(97, "DES/CBC/PKCS7Padding"),

        // 3DES, key length 128/192 bits, block size 8bytes
        DESEDE_ECB_NOPADDING(98, "DESede/ECB/NoPadding"),
        DESEDE_CBC_NOPADDING(99, "DESede/CBC/NoPadding"),
        DESEDE_ECB_PKCS7PADDING(100, "DESede/ECB/PKCS7Padding"),
        DESEDE_CBC_PKCS7PADDING(101, "DESede/CBC/PKCS7Padding"),

        // SM4, key length 128 bits, block size 16bytes
        SM4_ECB_NOPADDING(102, "SM4/ECB/NoPadding"),
        SM4_CBC_NOPADDING(103, "SM4/CBC/NoPadding"),
        SM4_ECB_PKCS7PADDING(104, "SM4/ECB/PKCS7Padding"),
        SM4_CBC_PKCS7PADDING(105, "SM4/CBC/PKCS7Padding");

        private String algorithm;
        private int index;
        Algorithm(int index, String algorithm) {
            this.algorithm = algorithm;
            this.index = index;
        }

        public int getIndex() {
            return index;
        }

        public String getAlgorithm() {
            return algorithm;
        }

        public static Algorithm valuesOf(String algorithm) {
            for(Algorithm c : values()) {
                if(c.algorithm.equals(algorithm)) {
                    return c;
                }
            }
            return UNKNOWN;
        }
    }

    Algorithm mAlgorithm = Algorithm.UNKNOWN;
    private ICrypto mICrypto = null;
    private boolean mInited = false;
    private int mType = -1;

    /**
     * 获取YiCrypto实例
     * @return YiCrypto实例
     * @throws YiCryptoException 当算法不存在时
     */
    public static YiSMCore getInstance(String algorithm) throws YiCryptoException {
        return new YiSMCore(algorithm);
    }

    // 不允许外部实例化
    private YiSMCore(String algorithm)  throws YiCryptoException {
        mAlgorithm = Algorithm.valuesOf(algorithm);
        if(mAlgorithm == Algorithm.UNKNOWN) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
        }

        if((mAlgorithm.getIndex() >= Algorithm.MD5.getIndex() &&
                mAlgorithm.getIndex() <= Algorithm.BLAKE_2B.getIndex())) {
            // digest
            mICrypto = new DigestImpl(mAlgorithm);
            mType = TYPE_DIGEST;
        }else if(mAlgorithm.getIndex() >= Algorithm.AES_ECB_NOPADDING.getIndex() &&
                mAlgorithm.getIndex() <= Algorithm.SM4_CBC_PKCS7PADDING.getIndex()) {
            // 对称加密
            mICrypto = new CipherImpl(mAlgorithm);
            mType = TYPE_CIPHER;
        }else if(mAlgorithm.getIndex() >= Algorithm.SM2WITHSM3_C1C2C3.getIndex() &&
                mAlgorithm.getIndex() <= Algorithm.SM2WITHBLAKE_2S_C1C3C2.getIndex()) {
            // sm2 加解密
            mICrypto = new GMCipherImpl(mAlgorithm);
            mType = TYPE_CIPHER;
        }else if(mAlgorithm.getIndex() >= Algorithm.RSA_NOPADDING.getIndex() &&
                mAlgorithm.getIndex() <= Algorithm.RSA_OAEPWITHSM3_MGF1PADDING.getIndex()) {
            // rsa 加解密
            mICrypto = new RSACipherImpl(mAlgorithm);
            mType = TYPE_CIPHER;
        }else if(mAlgorithm.getIndex() >= Algorithm.BLAKE_2SWITHSM2.getIndex() &&
                mAlgorithm.getIndex() <= Algorithm.SM3WITHSM2.getIndex()) {
            // sm2 签名
            mICrypto = new GMSigner(mAlgorithm);
            mType = TYPE_SIGNER;
        }else if(mAlgorithm.getIndex() >= Algorithm.MD5WITHRSA.getIndex() &&
                mAlgorithm.getIndex() <= Algorithm.SHA3_512WITHRSA_PSS.getIndex()) {
            // rsa 签名
            mICrypto = new RSASigner(mAlgorithm);
            mType = TYPE_SIGNER;
        }else if(mAlgorithm.getIndex() >= Algorithm.HMAC_MD5.getIndex() &&
                mAlgorithm.getIndex() <= Algorithm.HMAC_BLAKE_2B.getIndex()) {
            // 对称加密
            mICrypto = new HmacImpl(mAlgorithm);
            mType = TYPE_CIPHER;
        }

        if(mICrypto == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
        }

        mInited = false;
    }

    public YiSMCore setupForDigest() throws YiCryptoException {
        if(mICrypto instanceof DigestImpl) {
            mInited = true;
        } else {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_INIT_FAILED);
        }
        return this;
    }

    public YiSMCore setupForCipher(boolean forEncryption, YiCryptoKey cryptoKey) throws YiCryptoException {
        if(mICrypto != null && mType == TYPE_CIPHER) {
            mICrypto.init(forEncryption, cryptoKey);
            mInited = true;
        }else {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_INIT_FAILED);
        }

        return this;
    }

    public YiSMCore setupForSigner(boolean forSigning, YiCryptoKey cryptoKey) throws YiCryptoException {
        if(mICrypto != null && mType == TYPE_SIGNER) {
            mICrypto.init(forSigning, cryptoKey);
            mInited = true;
        }else {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_INIT_FAILED);
        }

        return this;
    }

    public YiSMCore update(byte[] input) throws YiCryptoException {
        if(!mInited) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_NOT_INIT);
        }
        mICrypto.update(input, 0, input.length);
        return this;
    }

    public YiSMCore update(byte[] input, int offset, int len) throws YiCryptoException {
        if(!mInited) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_NOT_INIT);
        }
        mICrypto.update(input, offset, len);
        return this;
    }

    public byte[] doFinal() throws YiCryptoException {
        if(!mInited) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_NOT_INIT);
        }
        return mICrypto.doFinal();
    }

    public byte[] doFinal(byte[] input) throws YiCryptoException {
        if(!mInited) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_NOT_INIT);
        }
        return mICrypto.doFinal(input, 0, input.length);
    }

    public byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException {
        if(!mInited) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_NOT_INIT);
        }
        return mICrypto.doFinal(input, offset, len);
    }

    public byte[] generateSignature() throws YiCryptoException {
        if(!mInited) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_NOT_INIT);
        }
        if(mType != TYPE_SIGNER || !(mICrypto instanceof ISigner)) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_ALGORITHM);
        }
        return mICrypto.doFinal();
    }

    public boolean verifySignature(byte[] signature) throws YiCryptoException {
        if(!mInited) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_NOT_INIT);
        }
        if(mType != TYPE_SIGNER || !(mICrypto instanceof ISigner)) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_ALGORITHM);
        }
        return ((ISigner) mICrypto).verifySignature(signature);
    }

    /**
     * 将二进制数据转换为十六进制字符串
     * @param bytes 二进制数据
     * @return 返回转换结果
     * @throws YiCryptoException 当输入数据非法时
     */
    public static String toHexString(byte[] bytes) throws YiCryptoException {
        return toHexString(bytes, 0, bytes.length);
    }

    /**
     * 将二进制数据转换为十六进制字符串
     * @param bytes 二进制数据
     * @param offset 数据起始位置
     * @param len 数据长度
     * @return 返回转换结果
     * @throws YiCryptoException 当输入数据非法时
     */
    public static String toHexString(byte[] bytes, int offset, int len) throws YiCryptoException {
        if(offset < 0 || len < 1 || (bytes != null && len > (bytes.length - offset))) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
        }

        if (bytes == null || bytes.length < len) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        char [] temp = new char[len * 2];
        char val;

        int slen = offset + len;
        for (int i = offset; i < slen; i++) {
            val = (char) (((bytes[i] & 0xf0) >> 4) & 0x0f);
            temp[(i - offset) * 2] = (char) (val > 9 ? val + 'A' - 10 : val + '0');

            val = (char) (bytes[i] & 0x0f);
            temp[(i - offset) * 2 + 1] = (char) (val > 9 ? val + 'A' - 10 : val + '0');
        }
        return new String(temp);
    }

    /**
     * 将十六进制字符串转换为二进制数组，前补0
     * @param asc 字符串
     * @return 转换结果
     * @throws YiCryptoException 当输入数据非法时
     */
    public static byte[] fromHexString(String asc) throws YiCryptoException {
        if((asc.length() % 2) == 0) {
            return fromHexString(asc, asc.length());
        }else {
            return fromHexString(asc, asc.length() + 1);
        }
    }

    /**
     * 将十六进制字符串转换为二进制数组，前补0
     * @param asc 字符串
     * @param len 将要转换的字符串长度，如12345，要转换为0x012345，则长度为6，前补0
     * @return 转换结果
     * @throws YiCryptoException 当输入数据非法时
     */
    public static byte[] fromHexString(String asc, int len) throws YiCryptoException {
        if(len < 0 || (len % 2 != 0)) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
        }

        if(asc == null || asc.isEmpty()) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }

        StringBuilder ascBuilder = new StringBuilder(asc);
        while (ascBuilder.length() < len) {
            ascBuilder.insert(0, "00000000000000000000000000000000"
                    .substring(0, len - ascBuilder.length()));
        }
        asc = ascBuilder.toString();
        byte [] abt = asc.getBytes();
        if (len >= 2) {
            len = len / 2;
        }
        byte [] bbt = new byte[len];
        int j, k;
        for (int p = 0; p < len; p++) {
            if ((abt[2 * p] >= '0') && (abt[2 * p] <= '9')) {
                j = abt[2 * p] - '0';
            } else if ((abt[2 * p] >= 'a') && (abt[2 * p] <= 'z')) {
                j = abt[2 * p] - 'a' + 0x0a;
            } else {
                j = abt[2 * p] - 'A' + 0x0a;
            }
            if ((abt[2 * p + 1] >= '0') && (abt[2 * p + 1] <= '9')) {
                k = abt[2 * p + 1] - '0';
            } else if ((abt[2 * p + 1] >= 'a') && (abt[2 * p + 1] <= 'z')) {
                k = abt[2 * p + 1] - 'a' + 0x0a;
            } else {
                k = abt[2 * p + 1] - 'A' + 0x0a;
            }
            int a = (j << 4) + k;
            byte b = (byte) a;
            bbt[p] = b;
        }
        return bbt;
    }
}
