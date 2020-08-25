package net.yiim.yismcore;




import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
import org.bouncycastle.crypto.engines.SM4Engine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import java.io.ByteArrayOutputStream;

final class CipherImpl implements ICrypto {
    private BufferedBlockCipher mPaddingCipher;
    private BlockCipher mCipher;

    private YiSMCore.Algorithm algorithm;
    private byte[] noPaddingBuf;
    private byte[] buf;
    private int blockSize;
    private int paddingBufOffset;
    private ByteArrayOutputStream bout;

    CipherImpl(YiSMCore.Algorithm algorithm) {
        switch (algorithm) {
            case AES_ECB_NOPADDING:
                mCipher = new AESEngine();
                break;
            case AES_CBC_NOPADDING:
                mCipher = new CBCBlockCipher(new AESEngine());
                break;
            case AES_ECB_PKCS7PADDING:
                mPaddingCipher = new PaddedBufferedBlockCipher(new AESEngine(), new PKCS7Padding());
                break;
            case AES_CBC_PKCS7PADDING:
                mPaddingCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new AESEngine()), new PKCS7Padding());
                break;
            case DES_ECB_NOPADDING:
                mCipher = new DESEngine();
                break;
            case DES_CBC_NOPADDING:
                mCipher = new CBCBlockCipher(new DESEngine());
                break;
            case DES_ECB_PKCS7PADDING:
                mPaddingCipher = new PaddedBufferedBlockCipher(new DESEngine(), new PKCS7Padding());
                break;
            case DES_CBC_PKCS7PADDING:
                mPaddingCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESEngine()), new PKCS7Padding());
                break;
            case DESEDE_ECB_NOPADDING:
                mCipher = new DESedeEngine();
                break;
            case DESEDE_CBC_NOPADDING:
                mCipher = new CBCBlockCipher(new DESedeEngine());
                break;
            case DESEDE_ECB_PKCS7PADDING:
                mPaddingCipher = new PaddedBufferedBlockCipher(new DESedeEngine(), new PKCS7Padding());
                break;
            case DESEDE_CBC_PKCS7PADDING:
                mPaddingCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new DESedeEngine()), new PKCS7Padding());
                break;
            case SM4_ECB_NOPADDING:
                mCipher = new SM4Engine();
                break;
            case SM4_CBC_NOPADDING:
                mCipher = new CBCBlockCipher(new SM4Engine());
                break;
            case SM4_ECB_PKCS7PADDING:
                mPaddingCipher = new PaddedBufferedBlockCipher(new SM4Engine(), new PKCS7Padding());
                break;
            case SM4_CBC_PKCS7PADDING:
                mPaddingCipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new SM4Engine()), new PKCS7Padding());
                break;
        }
        if(mPaddingCipher != null) {
            blockSize = mPaddingCipher.getBlockSize();
        }else {
            blockSize = mCipher.getBlockSize();
        }
        buf = new byte[blockSize * 2];
        noPaddingBuf = new byte[blockSize * 2];
        paddingBufOffset = 0;
        bout = new ByteArrayOutputStream(blockSize * 2);
        this.algorithm = algorithm;
    }

    public CipherImpl init(boolean forEncryption, YiCryptoKey cryptoKey) throws YiCryptoException {
        // check key parameter
        if(cryptoKey == null || cryptoKey.getSymmetricKey() == null ||
                cryptoKey.getSymmetricKey().length < 1 ||
                (cryptoKey.getSymmetricKey().length % 8) != 0) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
        }

        boolean isCBC = false;
        if((mPaddingCipher != null &&
                (mPaddingCipher.getUnderlyingCipher() instanceof CBCBlockCipher)) ||
                (mCipher instanceof CBCBlockCipher)) {
            isCBC = true;
        }

        // check iv bytes
        if(isCBC && (cryptoKey.getIV() == null || cryptoKey.getIV().length < blockSize)) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_IV);
        }

        if((algorithm.getIndex() >= YiSMCore.Algorithm.AES_ECB_NOPADDING.getIndex() &&
                algorithm.getIndex() <= YiSMCore.Algorithm.AES_CBC_PKCS7PADDING.getIndex())) {
            // AES
            if((cryptoKey.getSymmetricKey().length != 16 &&
                    cryptoKey.getSymmetricKey().length != 24 &&
                    cryptoKey.getSymmetricKey().length != 32)) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }else if(algorithm.getIndex() >= YiSMCore.Algorithm.DES_ECB_NOPADDING.getIndex() &&
                algorithm.getIndex() <= YiSMCore.Algorithm.DES_CBC_PKCS7PADDING.getIndex()) {
            // DES
            if(cryptoKey.getSymmetricKey().length != 8) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }else if((algorithm.getIndex() >= YiSMCore.Algorithm.SM4_ECB_NOPADDING.getIndex() &&
                algorithm.getIndex() <= YiSMCore.Algorithm.SM4_CBC_PKCS7PADDING.getIndex())) {
            // SM4
            if(cryptoKey.getSymmetricKey().length != 16) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }else if(algorithm.getIndex() >= YiSMCore.Algorithm.DESEDE_ECB_NOPADDING.getIndex() &&
                algorithm.getIndex() <= YiSMCore.Algorithm.DESEDE_CBC_PKCS7PADDING.getIndex()) {
            // DESede DESede3
            if(cryptoKey.getSymmetricKey().length != 16 && cryptoKey.getSymmetricKey().length != 24) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
        }


        KeyParameter keyParameter = new KeyParameter(cryptoKey.getSymmetricKey());
        if(mPaddingCipher != null) {
            if(isCBC) {
                ParametersWithIV parametersWithIV = new ParametersWithIV(keyParameter,
                        cryptoKey.getIV(), 0, blockSize);
                mPaddingCipher.init(forEncryption, parametersWithIV);
            }else {
                mPaddingCipher.init(forEncryption, keyParameter);
            }
        }else {
            if(isCBC) {
                ParametersWithIV parametersWithIV = new ParametersWithIV(keyParameter,
                        cryptoKey.getIV(), 0, blockSize);
                mCipher.init(forEncryption, parametersWithIV);
            }else {
                mCipher.init(forEncryption, keyParameter);
            }
        }
        return this;
    }

    @Override
    public CipherImpl update(byte[] input, int offset, int len) throws YiCryptoException {
        try {
            if(paddingBufOffset > 0) {
                int nLen = Math.min(len, blockSize - paddingBufOffset);
                System.arraycopy(input, offset, noPaddingBuf, paddingBufOffset, nLen);
                paddingBufOffset += nLen;
                len -= nLen;
                offset += nLen;

                if (paddingBufOffset == blockSize) {
                    int size = -1;
                    if(mPaddingCipher != null) {
                        size = mPaddingCipher.processBytes(noPaddingBuf, 0, blockSize, buf, 0);
                    }else {
                        size = mCipher.processBlock(noPaddingBuf, 0, buf, 0);
                    }
                    if(size > 0) {
                        bout.write(buf, 0, size);
                    }
                    paddingBufOffset = 0;
                }
            }

            while (len > 0) {
                int size = -1;
                if(len - blockSize > 0) {
                    if(mPaddingCipher != null) {
                        size = mPaddingCipher.processBytes(input, offset, blockSize, buf, 0);
                    }else {
                        size = mCipher.processBlock(input, offset, buf, 0);
                    }
                    len -= blockSize;
                    offset += blockSize;
                }else {
                    if(mPaddingCipher != null) {
                        size = mPaddingCipher.processBytes(input, offset, len, buf, 0);
                    }else {
                        System.arraycopy(input, offset, noPaddingBuf, paddingBufOffset, len);
                        paddingBufOffset += len;
                    }
                    len = 0;
                }
                if(size > 0) {
                    bout.write(buf, 0, size);
                }
            }
        }catch (Exception ex) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_CRYPT_FAILED);
        }

        return this;
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        try {
            int size = -1;
            if(mPaddingCipher != null) {
                size = mPaddingCipher.doFinal(buf, 0);
            }else {
                if(paddingBufOffset >= blockSize) {
                    size = mCipher.processBlock(noPaddingBuf, 0, buf, 0);
                    paddingBufOffset -= blockSize;
                }

                if (paddingBufOffset != 0) {
                    throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
                }
            }
            if(size > 0) {
                bout.write(buf, 0, size);
            }
        } catch (InvalidCipherTextException e) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_CRYPT_FAILED);
        }
        return bout.toByteArray();
    }

    @Override
    public byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException {
        update(input, offset, len);
        return doFinal();
    }
}
