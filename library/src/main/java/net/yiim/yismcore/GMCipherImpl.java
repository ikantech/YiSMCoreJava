package net.yiim.yismcore;


import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.*;
import org.bouncycastle.crypto.engines.SM2Engine;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;

/**
 * Created by ikantech on 19-10-14.
 */
final class GMCipherImpl implements ICrypto {
    private SM2Engine engine;
    private ByteArrayOutputStream bout;

    GMCipherImpl(YiSMCore.Algorithm algorithm) throws YiCryptoException {
        switch (algorithm) {
            case SM2WITHSM3_C1C2C3:
                engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C2C3);
                break;
            case SM2WITHSM3_C1C3C2:
                engine = new SM2Engine(new SM3Digest(), SM2Engine.Mode.C1C3C2);
                break;
            case SM2WITHSHA256_C1C2C3:
                engine = new SM2Engine(new SHA256Digest(), SM2Engine.Mode.C1C2C3);
                break;
            case SM2WITHSHA256_C1C3C2:
                engine = new SM2Engine(new SHA256Digest(), SM2Engine.Mode.C1C3C2);
                break;
            case SM2WITHSHA3_256_C1C2C3:
                engine = new SM2Engine(new SHA3Digest(256), SM2Engine.Mode.C1C2C3);
                break;
            case SM2WITHSHA3_256_C1C3C2:
                engine = new SM2Engine(new SHA3Digest(256), SM2Engine.Mode.C1C3C2);
                break;
            case SM2WITHBLAKE_2S_C1C2C3:
                engine = new SM2Engine(new Blake2sDigest(), SM2Engine.Mode.C1C2C3);
                break;
            case SM2WITHBLAKE_2S_C1C3C2:
                engine = new SM2Engine(new Blake2sDigest(), SM2Engine.Mode.C1C3C2);
                break;
            default:
                throw new YiCryptoException(YiCryptoErrorCode.ERR_NO_SUCH_ALGORITHM);
        }
        bout = new ByteArrayOutputStream(512);
    }

    public GMCipherImpl init(boolean forEncryption, YiCryptoKey cryptoKey) throws YiCryptoException {
        if (forEncryption) {
            CipherParameters parameters = cryptoKey.getSM2PublicKeyParameters();
            if(parameters instanceof ParametersWithID) {
                parameters = ((ParametersWithID) parameters).getParameters();
            }
            if(parameters == null) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }

            ParametersWithRandom parametersWithRandom = new ParametersWithRandom(
                    parameters, new SecureRandom());
            engine.init(true, parametersWithRandom);
        }else {
            CipherParameters parameters = cryptoKey.getSM2PrivateParameters();
            if(parameters instanceof ParametersWithID) {
                parameters = ((ParametersWithID) parameters).getParameters();
            }
            if(parameters == null) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_KEY);
            }
            engine.init(false, parameters);
        }
        return this;
    }

    @Override
    public GMCipherImpl update(byte[] input, int offset, int len) throws YiCryptoException {
        bout.write(input, offset, len);
        return this;
    }

    @Override
    public byte[] doFinal() throws YiCryptoException {
        byte[] bytes = bout.toByteArray();
        try {
            if(bytes == null || bytes.length < 1) {
                throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
            }
            return engine.processBlock(bytes, 0, bytes.length);
        } catch (InvalidCipherTextException e) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_CRYPT_FAILED);
        }
    }

    @Override
    public byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException {
        update(input, offset, len);
        return doFinal();
    }
}
