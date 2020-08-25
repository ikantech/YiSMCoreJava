package net.yiim.yismcore;

/**
 * Created by ikantech on 19-11-22.
 */
interface ISigner extends ICrypto {

    byte[] generateSignature() throws YiCryptoException;

    boolean verifySignature(byte[] signature) throws YiCryptoException;
}
