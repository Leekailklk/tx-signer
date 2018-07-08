package io.bytom.common;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class NonHardenedChild {

    public static byte[] HMacSha512(byte[] data, byte[] key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException
    {
        SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA512");
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(signingKey);
        return mac.doFinal(data);
    }

    public static byte[] child(String hpath, String hxprv, String hxpub) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
//        String dataStr = "N"+hxpub.substring(0, hxpub.length()/2)+hpath;
//        byte[] data = Hex.decode(Hex.toHexString(dataStr.getBytes()));
        int dataLength = "N".getBytes().length+hxpub.getBytes().length/2+hpath.getBytes().length;
        byte[] data = new byte[dataLength];
        data[0] = "N".getBytes()[0];
        for (int i=1;i<hxpub.getBytes().length/2+1;i++) {
            data[i] = hxpub.getBytes()[i];
        }
        for (int i=hxpub.getBytes().length/2+1;i<dataLength;i++) {
            data[i] = hpath.getBytes()[i-hxpub.getBytes().length/2-1];
        }
        String keyStr = hxpub.substring(hxpub.length()/2, hxpub.length());
        byte[] key = Hex.decode(keyStr);
        byte[] res = HMacSha512(data, key);
        byte[] f = new byte[res.length/2];
        for (int i = 0; i < res.length/2; i++) {
            f[i] = res[i];
        }
        f = pruneIntermediateScalar(f);
        for (int i = 0; i < res.length/2; i++) {
            res[i] = f[i];
        }
        int carry = 0;
        int sum = 0;
        byte[] xprv = Hex.decode(hxprv);
        byte[] xpub = Hex.decode(hxpub);
        for (int i = 0; i < 32; i++) {
            int xprvInt = xprv[i] & 0xFF;
            int resInt = res[i] & 0xFF;
            sum = xprvInt + resInt + carry;
            res[i] = (byte)sum;
            carry = sum >> 8;
        }
        return res;
    }

    private static byte[] pruneIntermediateScalar(byte[] f) {
        f[0] &= 248; // clear bottom 3 bits
        f[29] &= 1; // clear 7 high bits
        f[30] = 0;  // clear 8 bits
        f[31] = 0;  // clear 8 bits
        return f;
    }
}


