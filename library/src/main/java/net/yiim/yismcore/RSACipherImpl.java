package net.yiim.yismcore;


import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;

import javax.crypto.spec.PSource;
import java.io.ByteArrayOutputStream;

final class RSACipherImpl implements ICrypto {
    private AsymmetricBlockCipher cipher;
    private ByteArrayOutputStream buf;
    private ByteArrayOutputStream bout;
    private boolean forEncryption;

    RSACipherImpl(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        switch (algorithm) {
            case RSA_NOPADDING:
                cipher = new RSABlindedEngine();
                break;
            case RSA_PKCS1PADDING:
                cipher = new PKCS1Encoding(new RSABlindedEngine());
                break;
            case RSA_OAEPWITHMD5_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new MD5Digest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA1_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA1Digest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA224_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA224Digest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA256_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA256Digest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA384_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA384Digest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA512_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA512Digest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA3_224_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA3Digest(224), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA3_256_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA3Digest(256), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA3_384_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA3Digest(384), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSHA3_512_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SHA3Digest(512), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHBLAKE_2S_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new Blake2sDigest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHBLAKE_2B_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new Blake2bDigest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            case RSA_OAEPWITHSM3_MGF1PADDING:
                cipher = new OAEPEncoding(new RSABlindedEngine(),
                        new SM3Digest(), PSource.PSpecified.DEFAULT.getValue());
                break;
            default:
                throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
        }
        bout = new ByteArrayOutputStream(1024);
    }

    @Override
    public ICrypto init(boolean forWhat, YiCryptoKey cryptoKey) throws YiCryptoException {
        if(cryptoKey.getRSAPrivateParameter() == null) {
            // public key
            if(cryptoKey.getRSAPublicParameter() == null) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
            cipher.init(forWhat, cryptoKey.getRSAPublicParameter());
        }else {
            cipher.init(forWhat, cryptoKey.getRSAPrivateParameter());
        }
        if(cipher.getInputBlockSize() < 0) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }
        this.forEncryption = forWhat;
        buf = new ByteArrayOutputStream(cryptoKey.getRSA_NBytes().length + 8);
        return this;
    }

    @Override
    public ICrypto update(byte[] input, int offset, int len) throws YiCryptoException {
        try {
            int expLen = len + buf.size();
            while (expLen >= cipher.getInputBlockSize()) {
                if (buf.size() < cipher.getInputBlockSize()) {
                    int iLen = cipher.getInputBlockSize() - buf.size();
                    if (iLen > 0) {
                        int l = Math.min(iLen, len);
                        buf.write(input, offset, l);
                        offset += l;
                        len -= l;
                    }
                }
                if (buf.size() == cipher.getInputBlockSize()) {
                    byte[] bufBytes = buf.toByteArray();
                    bout.write(cipher.processBlock(bufBytes, 0, bufBytes.length));
                    buf.reset();
                    expLen -= cipher.getInputBlockSize();
                }
            }

            if(len > 0) {
                buf.write(input, offset, len);
            }
            return this;
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_CRYPT_FAILED);
        }
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        try {
            if(forEncryption) {
                if(cipher instanceof RSABlindedEngine) {
                    // 加密，no padding情况下，长度必须等于InputBlockSize
                    if(buf.size() > 0 && buf.size() != cipher.getInputBlockSize()) {
                        throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PADDING);
                    }
                }
            }else {
                // 解密，所以长度不管是不是有填充，都必须等于InputBlockSize
                if(buf.size() > 0 && buf.size() != cipher.getInputBlockSize()) {
                    throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PADDING);
                }
            }
            if(buf.size() > 0) {
                byte[] bufBytes = buf.toByteArray();
                bout.write(cipher.processBlock(bufBytes, 0, bufBytes.length));
                buf.reset();
            }
            return bout.toByteArray();
        } catch (YiCryptoException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_CRYPT_FAILED);
        }
    }

    @Override
    public byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException {
        update(input, offset, len);
        return doFinal();
    }
}
