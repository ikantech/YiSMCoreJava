package net.yiim.yismcore;


import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;

/**
 * Created by ikantech on 19-9-2.
 */
final class DigestImpl implements ICrypto {
    private Digest mDigest;

    DigestImpl(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        switch (algorithm) {
            case MD5:
                mDigest = new MD5Digest();
                break;
            case SHA1:
                mDigest = new SHA1Digest();
                break;
            case SHA224:
                mDigest = new SHA224Digest();
                break;
            case SHA256:
                mDigest = new SHA256Digest();
                break;
            case SHA384:
                mDigest = new SHA384Digest();
                break;
            case SHA512:
                mDigest = new SHA512Digest();
                break;
            case SM3:
                mDigest = new SM3Digest();
                break;
            case SHA3_224:
                mDigest = new SHA3Digest(224);
                break;
            case SHA3_256:
                mDigest = new SHA3Digest(256);
                break;
            case SHA3_384:
                mDigest = new SHA3Digest(384);
                break;
            case SHA3_512:
                mDigest = new SHA3Digest(512);
                break;
            case BLAKE_2S:
                mDigest = new Blake2sDigest();
                break;
            case BLAKE_2B:
                mDigest = new Blake2bDigest();
                break;
            default:
                throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
        }
    }

    @Override
    public ICrypto init(boolean forWhat, YiCryptoKey cryptoKey) throws YiCryptoException {
        return this;
    }

    @Override
    public DigestImpl update(byte[] input, int offset, int len) throws YiCryptoException {
        mDigest.update(input, offset, len);
        return this;
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        int outputLen = mDigest.getDigestSize();
        byte[] retBytes = new byte[outputLen];
        mDigest.doFinal(retBytes, 0);
        return retBytes;
    }

    @Override
    public byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException {
        mDigest.update(input, offset, len);
        int outputLen = mDigest.getDigestSize();
        byte[] retBytes = new byte[outputLen];
        mDigest.doFinal(retBytes, 0);
        return retBytes;
    }
}
