package io.bytom.common;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;

public class NonHardenedChild {

    public static byte[] HMacSha512(byte[] data, byte[] key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException
    {
        SecretKeySpec signingKey = new SecretKeySpec(key, "HmacSHA512");
        Mac mac = Mac.getInstance("HmacSHA512");
        mac.init(signingKey);
        return mac.doFinal(data);
    }

    public static byte[] NHchild(byte[] path, byte[] xprv, byte[] xpub) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
//        int dataLength = 1+xpub.length/2+path.length;
//        byte[] data = new byte[dataLength];
        //begin build data
//        data[0] = (byte)'N';
//        for (int i=1;i<xpub.length/2+1;i++) {
//            data[i] = xpub[i];
//        }
//        for (int i=xpub.length/2+1;i<dataLength;i++) {
//            data[i] = path[i-xpub.length/2-1];
//        }
        //end build data
        String n = Hex.toHexString("N".getBytes());
        String hxpub = Hex.toHexString(xpub);
        String hpath = Hex.toHexString(path);

        String hdata = n + hxpub.substring(0, hxpub.length()/2) + hpath;
        byte[] data = Hex.decode(hdata);
        //begin build key
//        byte[] key = new byte[xpub.length/2];
//        for (int i = 0; i < xpub.length/2; i++) {
//            key[i] = xpub[i+xpub.length/2];
//        }
        String hkey = hxpub.substring(hxpub.length()/2, hxpub.length());
        byte[] key = Hex.decode(hkey);
        //end build key
        byte[] res = HMacSha512(data, key);
        System.out.println("1. res: "+Hex.toHexString(res));
        //begin operate res[:32]
        byte[] f = new byte[res.length/2];
        for (int i = 0; i < res.length/2; i++) {
            f[i] = res[i];
        }
        f = pruneIntermediateScalar(f);
        for (int i = 0; i < res.length/2; i++) {
            res[i] = f[i];
        }
        //end operate res[:32]
        System.out.println("2. res: "+Hex.toHexString(res));

        //begin operate res[:32] again
        int carry = 0;
        int sum = 0;
        for (int i = 0; i < 32; i++) {
            int xprvInt = xprv[i] & 0xFF;
            int resInt = res[i] & 0xFF;
            sum = xprvInt + resInt + carry;
            res[i] = (byte)sum;
            carry = sum >> 8;
        }
        System.out.println("3. res: "+Hex.toHexString(res));

        if ((sum >> 8) != 0) {
            System.err.println("sum does not fit in 256-bit int");
        }
        //end operate res[:32] again
        return res;
    }

    private static byte[] pruneIntermediateScalar(byte[] f) {
        f[0] &= 248; // clear bottom 3 bits
        f[29] &= 1; // clear 7 high bits
        f[30] = 0;  // clear 8 bits
        f[31] = 0;  // clear 8 bits
        return f;
    }

    public static byte[] child(byte[] xprv, String[] hpaths) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        byte[][] paths = new byte[][]{
                Hex.decode(hpaths[0]),
                Hex.decode(hpaths[1])
        };
        byte[] res = xprv;
        for (int i = 0; i < hpaths.length; i++) {
            byte[] xpub = DeriveXpub.deriveXpub(res);
//            System.out.println("xpub: "+Hex.toHexString(xpub));
            res = NonHardenedChild.NHchild(paths[i], res, xpub);
        }
        return res;
    }
}


