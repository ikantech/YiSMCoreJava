package net.yiim.yismcore;

import org.junit.Assert;
import org.junit.Test;

/**
 * Created by ikantech on 19-9-2.
 */
public class CommonTest {
    @Test
    public void testToHexString() {
        byte[] bytes = new byte[]{0x61, 0x62, 0x63, 0x64, 0x65};

        try {
            String hexStr = YiSMCore.toHexString(bytes);
            Assert.assertEquals("6162636465", hexStr);

            hexStr = YiSMCore.toHexString(bytes, 1, 3);
            Assert.assertEquals("626364", hexStr);
        } catch (YiCryptoException e) {
            Assert.fail(e.toString());
        }
    }

    @Test
    public void testFromHexString() {
        try {
            byte[] bytes = YiSMCore.fromHexString("616263");
            Assert.assertArrayEquals(new byte[]{0x61, 0x62, 0x63}, bytes);

            bytes = YiSMCore.fromHexString("16263");
            Assert.assertArrayEquals(new byte[]{0x01, 0x62, 0x63}, bytes);

            bytes = YiSMCore.fromHexString("616263", 6);
            Assert.assertArrayEquals(new byte[]{0x61, 0x62, 0x63}, bytes);

            bytes = YiSMCore.fromHexString("16263", 8);
            Assert.assertArrayEquals(new byte[]{0x00, 0x01, 0x62, 0x63}, bytes);

            bytes = YiSMCore.fromHexString("616263", 4);
            Assert.assertArrayEquals(new byte[]{0x61, 0x62}, bytes);
        }catch (YiCryptoException e) {
            Assert.fail(e.toString());
        }
    }

    @Test
    public void testDefaultBase64() {
        try {
            byte[] bytes = YiSMCore.fromHexString("FEF161626FFE11");
            // default base64 padding
            Assert.assertEquals("/vFhYm/+EQ==", YiBase64.toBase64String(bytes));
            // default base64 nopadding
            Assert.assertEquals("/vFhYm/+EQ", YiBase64.toBase64StringNoPadding(bytes));
            // safe url base64
            Assert.assertEquals("_vFhYm_-EQ", YiBase64.toSafeUrlBase64String(bytes));

            Assert.assertEquals("/vFhYg==", YiBase64.toBase64String(bytes, 0, 4));
            Assert.assertEquals("/vFhYg", YiBase64.toBase64StringNoPadding(bytes, 0, 4));
            Assert.assertEquals("_vFhYg", YiBase64.toSafeUrlBase64String(bytes, 0, 4));

            Assert.assertArrayEquals(bytes, YiBase64.fromBase64String("/vFhYm/+EQ=="));
            Assert.assertArrayEquals(bytes, YiBase64.fromBase64String("/vFhYm/+EQ"));
            Assert.assertArrayEquals(bytes, YiBase64.fromSafeUrlBase64String("_vFhYm_-EQ"));
        }catch (YiCryptoException ex) {
            Assert.fail(ex.toString());
        }
    }

    @Test
    public void testCustomBase64() {
        try {
            byte[] bytes = YiSMCore.fromHexString("FEF161626FFE11");

            YiBase64 base64 = new YiBase64("g20q3TA1VUvJO4bQLMjCIkwRSmyBaFGPul95Hhi8DXtE6zc7_-opNefdxKWYZnrs");

            Assert.assertEquals("s7TlSisr3L==", base64.encode(bytes));
            Assert.assertEquals("s7TlSisr3L", base64.encode(bytes, 0, bytes.length, false));
            Assert.assertEquals("s7TlSu==", base64.encode(bytes, 0, 4));
            Assert.assertEquals("s7TlSu", base64.encode(bytes, 0, 4, false));

            Assert.assertArrayEquals(bytes, base64.decode("s7TlSisr3L=="));
            Assert.assertArrayEquals(bytes, base64.decode("s7TlSisr3L"));
        }catch (YiCryptoException ex) {
            Assert.fail(ex.toString());
        }
    }
}
