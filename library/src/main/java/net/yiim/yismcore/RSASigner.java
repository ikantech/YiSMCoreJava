package net.yiim.yismcore;


import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;

final class RSASigner implements ISigner {
    private Signer mSigner = null;
    private boolean mForSigning = false;

    RSASigner(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        switch (algorithm) {
            case MD5WITHRSA:
                mSigner = new RSADigestSigner(new MD5Digest());
                break;
            case SHA1WITHRSA:
                mSigner = new RSADigestSigner(new SHA1Digest());
                break;
            case SHA224WITHRSA:
                mSigner = new RSADigestSigner(new SHA224Digest());
                break;
            case SHA256WITHRSA:
                mSigner = new RSADigestSigner(new SHA256Digest());
                break;
            case SHA384WITHRSA:
                mSigner = new RSADigestSigner(new SHA384Digest());
                break;
            case SHA512WITHRSA:
                mSigner = new RSADigestSigner(new SHA512Digest());
                break;
            case SHA3_224WITHRSA:
                mSigner = new RSADigestSigner(new SHA3Digest(224));
                break;
            case SHA3_256WITHRSA:
                mSigner = new RSADigestSigner(new SHA3Digest(256));
                break;
            case SHA3_384WITHRSA:
                mSigner = new RSADigestSigner(new SHA3Digest(384));
                break;
            case SHA3_512WITHRSA:
                mSigner = new RSADigestSigner(new SHA3Digest(512));
                break;
            case MD5WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new MD5Digest(), 16);
                break;
            case SHA1WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA1Digest(), 20);
                break;
            case SHA224WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA224Digest(), 28);
                break;
            case SHA256WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA256Digest(), 32);
                break;
            case SHA384WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA384Digest(), 48);
                break;
            case SHA512WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA512Digest(), 64);
                break;
            case SHA3_224WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA3Digest(224), 28);
                break;
            case SHA3_256WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA3Digest(256), 32);
                break;
            case SHA3_384WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA3Digest(384), 48);
                break;
            case SHA3_512WITHRSA_PSS:
                mSigner = new PSSSigner(new RSABlindedEngine(), new SHA3Digest(512), 64);
                break;
            default:
                throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
        }
    }

    @Override
    public byte[] generateSignature() throws YiCryptoException {
        if(mForSigning) {
            try {
                return mSigner.generateSignature();
            } catch (Exception e) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_SIGN_FAILED);
            }
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
    }

    @Override
    public boolean verifySignature(byte[] signature) throws YiCryptoException {
        if(!mForSigning && signature != null && signature.length > 0) {
            try {
                return mSigner.verifySignature(signature);
            } catch (Exception e) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_VERIFY_FAILED);
            }
        }
        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
    }

    @Override
    public ICrypto init(boolean forWhat, YiCryptoKey cryptoKey) throws YiCryptoException {
        try {
            if(cryptoKey.getRSAPrivateParameter() == null) {
                // public key
                if(cryptoKey.getRSAPublicParameter() == null) {
                    throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
                }
                mSigner.init(forWhat, cryptoKey.getRSAPublicParameter());
            }else {
                mSigner.init(forWhat, cryptoKey.getRSAPrivateParameter());
            }
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ALGORITHM_INIT_FAILED);
        }
        mForSigning = forWhat;
        return this;
    }

    @Override
    public ICrypto update(byte[] input, int offset, int len) throws YiCryptoException {
        mSigner.update(input, offset, len);
        return this;
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        return generateSignature();
    }

    @Override
    public byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException {
        update(input, offset, len);
        return generateSignature();
    }
}
