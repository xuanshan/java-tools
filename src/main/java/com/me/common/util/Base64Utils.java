package com.me.common.util;

import javax.xml.bind.DatatypeConverter;
import java.nio.charset.Charset;

public abstract class Base64Utils {

    private static final Charset DEFAULT_CHARSET = Charset.forName("UTF-8");

    private static final Base64Delegate delegate;

    static {
        Base64Delegate delegateToUse = null;
        if (ClassUtils.isPresent("org.apache.commons.codec.binary.Base64", Base64Utils.class.getClassLoader())) {
            delegateToUse = new CommonsCodecBase64Delegate();
        }
        delegate = delegateToUse;
    }

    private static void assertDelegateAvailable() {
        if (delegate == null) {
            throw new IllegalArgumentException("Apache Commons Codec found - Base64 encoding between byte arrays not supported");
        }
    }

    public static byte[] encode(byte[] src) {
        assertDelegateAvailable();
        return delegate.encode(src);
    }

    public static byte[] decode(byte[] src) {
        assertDelegateAvailable();
        return delegate.decode(src);
    }

    public static byte[] encodeUrlSafe(byte[] src) {
        assertDelegateAvailable();
        return delegate.encodeUrl(src);
    }

    public static byte[] decodeUrl(byte[] src) {
        assertDelegateAvailable();
        return delegate.decodeUrl(src);
    }

    public static String encodeToString(byte[] src) {
        if (src == null) {
            return null;
        }
        if (src.length == 0) {
            return "";
        }

        if (delegate != null) {
            return new String(delegate.encode(src), DEFAULT_CHARSET);
        } else {
            return DatatypeConverter.printBase64Binary(src);
        }
    }

    public static byte[] decodeFromString(String src) {
        if (src == null) {
            return null;
        }
        if (src.length() == 0) {
            return new byte[0];
        }

        if (delegate != null) {
            return delegate.decode(src.getBytes(DEFAULT_CHARSET));
        } else {
            return DatatypeConverter.parseBase64Binary(src);
        }
    }

    public static String encodeToUrlString(byte[] src) {
        assertDelegateAvailable();
        return new String(delegate.encodeUrl(src), DEFAULT_CHARSET);
    }

    public static byte[] decodeFromUrlString(String src) {
        assertDelegateAvailable();
        return delegate.decodeUrl(src.getBytes(DEFAULT_CHARSET));
    }


    interface Base64Delegate {

        byte[] encode(byte[] src);

        byte[] decode(byte[] src);

        byte[] encodeUrl(byte[] src);

        byte[] decodeUrl(byte[] src);
    }

    static class CommonsCodecBase64Delegate implements Base64Delegate {

        private final org.apache.commons.codec.binary.Base64 base64 =
                new org.apache.commons.codec.binary.Base64();

        private final org.apache.commons.codec.binary.Base64 base64UrlSafe =
                new org.apache.commons.codec.binary.Base64(0, null, true);

        @Override
        public byte[] encode(byte[] src) {
            return this.base64.encode(src);
        }

        @Override
        public byte[] decode(byte[] src) {
            return this.base64.decode(src);
        }

        @Override
        public byte[] encodeUrl(byte[] src) {
            return this.base64UrlSafe.encode(src);
        }

        @Override
        public byte[] decodeUrl(byte[] src) {
            return this.base64UrlSafe.decode(src);
        }

    }

}
