package net.yiim.yismcore;


import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;

public class YiBase64 {
    private Base64Encoder encoder;
    private static YiBase64 defaultEncoder = null;

    public YiBase64() {
        this.encoder = new Base64Encoder();
    }

    public YiBase64(String encodingTable) throws YiCryptoException {
        try {
            this.encoder = new Base64Encoder(encodingTable);
        } catch (UnsupportedEncodingException e) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_PARAMS);
        }
    }

    public String encode(byte[] data, boolean padding) throws YiCryptoException {
        if(data == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        return encode(data, 0, data.length, padding);
    }

    public String encode(byte[] data) throws YiCryptoException {
        if(data == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        return encode(data, 0, data.length, true);
    }

    public String encode(byte[] data, int off, int length) throws YiCryptoException {
        return encode(data, off, length, true);
    }

    public String encode(byte[] data, int off, int length, boolean padding) throws YiCryptoException {
        if(data == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }

        int len = (length + 2) / 3 * 4;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

        try {
            encoder.encode(data, off, length, bOut);
            String retStr = new String(bOut.toByteArray(), "ASCII");
            if(!padding) {
                retStr = retStr.replaceAll("=", "");
            }
            return retStr;
        } catch (Exception e) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_BASE64_ENCODE_FAILED);
        }
    }

    public byte[] decode(String data) throws YiCryptoException {
        if(data == null || data.length() < 1) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        int mod4 = data.length() % 4;
        if(mod4 > 0){
            data = data + "====".substring(mod4);
        }
        int len = data.length() / 4 * 3;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);

        try {
            encoder.decode(data, bOut);
        } catch (Exception e) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_BASE64_DECODE_FAILED);
        }

        return bOut.toByteArray();
    }

    private static String toBase64String(byte[] data, int off, int length,
                                         boolean safeUrl, boolean padding) throws YiCryptoException {
        if(defaultEncoder == null) {
            synchronized (YiBase64.class) {
                if(defaultEncoder == null) {
                    defaultEncoder = new YiBase64();
                }
            }
        }
        if(data == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        String retStr = defaultEncoder.encode(data, off, length, padding);
        if(safeUrl) {
            retStr =  retStr.replace('+', '-');
            retStr = retStr.replace('/', '_');
        }
        return retStr;
    }

    public static String toBase64String(byte[] data) throws YiCryptoException {
        if(data == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        return toBase64String(data, 0, data.length, false, true);
    }

    public static String toBase64String(byte[] data, int off, int length) throws YiCryptoException {
        return toBase64String(data, off, length, false, true);
    }

    public static String toBase64StringNoPadding(byte[] data) throws YiCryptoException {
        if(data == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        return toBase64String(data, 0, data.length, false, false);
    }

    public static String toBase64StringNoPadding(byte[] data, int off, int length) throws YiCryptoException {
        return toBase64String(data, off, length, false, false);
    }

    public static String toSafeUrlBase64String(byte[] data) throws YiCryptoException {
        if(data == null) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        return toBase64String(data, 0, data.length, true, false);
    }

    public static String toSafeUrlBase64String(byte[] data, int off, int length) throws YiCryptoException {
        return toBase64String(data, off, length, true, false);
    }

    private static byte[] fromBase64String(String data, boolean safeUrl) throws YiCryptoException {
        if(defaultEncoder == null) {
            synchronized (YiBase64.class) {
                if(defaultEncoder == null) {
                    defaultEncoder = new YiBase64();
                }
            }
        }
        if(data == null || data.length() < 1) {
            throw new YiCryptoException(YiCryptoErrorCode.ERR_ILLEGAL_INPUT);
        }
        if(safeUrl) {
            data = data.replace('-', '+');
            data = data.replace('_', '/');
        }
        return defaultEncoder.decode(data);
    }

    public static byte[] fromBase64String(String data) throws YiCryptoException {
        return fromBase64String(data, false);
    }

    public static byte[] fromSafeUrlBase64String(String data) throws YiCryptoException {
        return fromBase64String(data, true);
    }
}
