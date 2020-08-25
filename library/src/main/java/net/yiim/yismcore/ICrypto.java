package net.yiim.yismcore;

interface ICrypto {
    ICrypto init(boolean forWhat, YiCryptoKey cryptoKey) throws YiCryptoException;

    ICrypto update(byte[] input, int offset, int len) throws YiCryptoException;

    byte[] doFinal() throws YiCryptoException;
    byte[] doFinal(byte[] input, int offset, int len) throws YiCryptoException;
}
