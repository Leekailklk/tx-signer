package io.bytom.common;

import com.google.crypto.tink.subtle.Ed25519;

public class DeriveXpub {
    public static byte[] deriveXpub(byte[] xprv) {
        byte[] xpub = new byte[xprv.length];
        byte[] scalar = new byte[xprv.length/2];
        for (int i = 0; i < xprv.length / 2; i++) {
            scalar[i] = xprv[i];
        }
        byte[] buf = Ed25519.scalarMultWithBaseToBytes(scalar);
        for (int i = 0; i < buf.length; i++) {
            xpub[i] = buf[i];
        }
        for (int i = xprv.length/2; i < xprv.length; i++) {
            xpub[i] = xprv[i];
        }
        return xpub;
    }
}
