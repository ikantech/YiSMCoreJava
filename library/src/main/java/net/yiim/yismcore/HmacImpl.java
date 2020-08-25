package net.yiim.yismcore;


import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

final class HmacImpl implements ICrypto {
    HMac hMac;

    HmacImpl(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        switch (algorithm) {
            case HMAC_MD5:
                hMac = new HMac(new MD5Digest());
                break;
            case HMAC_SHA1:
                hMac = new HMac(new SHA1Digest());
                break;
            case HMAC_SHA224:
                hMac = new HMac(new SHA224Digest());
                break;
            case HMAC_SHA256:
                hMac = new HMac(new SHA256Digest());
                break;
            case HMAC_SHA384:
                hMac = new HMac(new SHA384Digest());
                break;
            case HMAC_SHA512:
                hMac = new HMac(new SHA512Digest());
                break;
            case HMAC_SHA3_224:
                hMac = new HMac(new SHA3Digest(224));
                break;
            case HMAC_SHA3_256:
                hMac = new HMac(new SHA3Digest(256));
                break;
            case HMAC_SHA3_384:
                hMac = new HMac(new SHA3Digest(384));
                break;
            case HMAC_SHA3_512:
                hMac = new HMac(new SHA3Digest(512));
                break;
            case HMAC_SM3:
                hMac = new HMac(new SM3Digest());
                break;
            case HMAC_BLAKE_2S:
                hMac = new HMac(new Blake2sDigest());
                break;
            case HMAC_BLAKE_2B:
                hMac = new HMac(new Blake2bDigest());
                break;
            default:
                throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
        }
    }

    @Override
    public ICrypto init(boolean forWhat, YiCryptoKey cryptoKey) throws YiCryptoException {
        if(cryptoKey == null || cryptoKey.getSymmetricKey() == null ||
                cryptoKey.getSymmetricKey().length < 1) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        hMac.init(new KeyParameter(cryptoKey.getSymmetricKey()));
        return this;
    }

    @Override
    public ICrypto update(byte[] input, int offset, int len) throws YiCryptoException {
        try {
            hMac.update(input, offset, len);
            return this;
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_HMAC_UPDATE_FAILED);
        }
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        try {
            byte[] ret = new byte[hMac.getMacSize()];
            hMac.doFinal(ret, 0);
            return ret;
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_HMAC_FAILED);
        }
    }

    @Override
    public byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException {
        update(input, offset, len);
        return doFinal();
    }
}
