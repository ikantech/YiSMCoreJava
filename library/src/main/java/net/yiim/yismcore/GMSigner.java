package net.yiim.yismcore;

import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.signers.DSAEncoding;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.util.BigIntegers;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;

/**
 * Created by ikantech on 19-11-22.
 */
final class GMSigner implements ISigner {
    private YiSMCore.Algorithm mAlgorithm;
    private SM2Signer mSigner;
    private boolean mForSigning;

    GMSigner(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        mAlgorithm = algorithm;
    }

    @Override
    public GMSigner init(boolean forSigning, YiCryptoKey cryptoKey) throws YiCryptoException {
        Digest digest;
        switch (mAlgorithm) {
            case SHA256WITHSM2:
                digest = new SHA256Digest();
                break;
            case SHA3_256WITHSM2:
                digest = new SHA3Digest(256);
                break;
            case BLAKE_2SWITHSM2:
                digest = new Blake2sDigest();
                break;
            default:
                digest = new SM3Digest();
                break;
        }
        mSigner = new SM2Signer(new SM2RSEncoding(), digest);
        if(forSigning) {
            if(cryptoKey.getSM2PrivateParameters() == null) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
            mSigner.init(true, cryptoKey.getSM2PrivateParameters());
        }else {
            if(cryptoKey.getSM2PublicKeyParameters() == null) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
            mSigner.init(false, cryptoKey.getSM2PublicKeyParameters());
        }
        mForSigning = forSigning;
        return this;
    }

    @Override
    public ISigner update(byte[] input, int offset, int len) throws YiCryptoException {
        mSigner.update(input, offset, len);
        return this;
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        return generateSignature();
    }

    @Override
    public byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException {
        mSigner.update(input, offset, len);
        return generateSignature();
    }

    @Override
    public byte[] generateSignature() throws YiCryptoException {
        try {
            if(mForSigning) {
                return mSigner.generateSignature();
            }
        } catch (CryptoException e) {
            // throw exception
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_SIGN_FAILED);
    }

    @Override
    public boolean verifySignature(byte[] signature) throws YiCryptoException {
        try {
            if(!mForSigning) {
                return mSigner.verifySignature(signature);
            }
        }catch (Exception ex) {
            // throw exception
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_VERIFY_FAILED);
    }

    private class SM2RSEncoding implements DSAEncoding {

        @Override
        public BigInteger[] decode(BigInteger n, byte[] encoding) throws IOException {
            if(encoding == null || encoding.length != 64) {
                throw new IllegalArgumentException("Malformed signature");
            }
            byte[] buf = new byte[32];
            System.arraycopy(encoding, 0, buf, 0, 32);
            BigInteger r = checkValue(n, new BigInteger(1, buf));
            System.arraycopy(encoding, 32, buf, 0, 32);
            BigInteger s = checkValue(n, new BigInteger(1, buf));
            return new BigInteger[]{r, s};
        }

        @Override
        public byte[] encode(BigInteger n, BigInteger r, BigInteger s) throws IOException {
            ByteArrayOutputStream bout = new ByteArrayOutputStream(65);
            bout.write(BigIntegers.asUnsignedByteArray(32, checkValue(n, r)));
            bout.write(BigIntegers.asUnsignedByteArray(32, checkValue(n, s)));
            return bout.toByteArray();
        }

        BigInteger checkValue(BigInteger n, BigInteger x)
        {
            if (x.signum() < 0 || (null != n && x.compareTo(n) >= 0))
            {
                throw new IllegalArgumentException("Value out of range");
            }

            return x;
        }
    }
}
