package io.bytom.api;

import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPrivateKeySpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;

public class Signer {

    public static final int PrivateKeySize = 128;
    public static final int PublicKeySize = 64;
    public static final int SignatureSize = 128;


    public static byte[] signFn(byte[] privateKey, String message) {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        Signature sgr = null;
        byte[] result = null;

        try {
            sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
            EdDSAPrivateKeySpec privKey = new EdDSAPrivateKeySpec(privateKey, spec);
            PrivateKey sKey = new EdDSAPrivateKey(privKey);
            sgr.initSign(sKey);

            sgr.update(message.getBytes());
            result = sgr.sign();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        return result;

    }

    public static String sign(String privateKey, String message) throws Exception {
        if (privateKey.length() != PrivateKeySize) {
            throw new Exception("ed25519: bad private key length: " + PrivateKeySize);
        }
        // need pre-32 byte
        byte[] rootPriv = Hex.decode(privateKey.substring(0, privateKey.length() / 2));

        byte[] sigResult = signFn(rootPriv, message);
        return Hex.toHexString(sigResult);
    }

    public static boolean verifyFn(byte[] publicKey, String message, byte[] sigResult) {
        EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
        try {
            Signature sgr = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
            EdDSAPublicKeySpec pubKey = new EdDSAPublicKeySpec(publicKey, spec);
            PublicKey vKey = new EdDSAPublicKey(pubKey);
            sgr.initVerify(vKey);

            sgr.update(message.getBytes());
            return sgr.verify(sigResult);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static boolean verify(String publicKeyHex, String message, String sigResultHex) throws Exception {
        if (publicKeyHex.length() != PublicKeySize) {
            throw new Exception("ed25519: bad public key length: " + PublicKeySize);
        }
        if (sigResultHex.length() != SignatureSize) {
            throw new Exception("ed25519: bad public key length: " + SignatureSize);
        }
        byte[] publicKey = Hex.decode(publicKeyHex);
        byte[] sigResult = Hex.decode(sigResultHex);
        return verifyFn(publicKey, message, sigResult);
    }

    public static void main(String[] args) throws Exception {
//        byte[] rootPriv = Hex.decode("d343266054d9c8b175d85c755a87b77d44295c5c7e5afb56c5c2efba19d882ae6ddbc4126fcb632d192d67006185b1ce77f1614db167072e0b3cae1f8824cd1a".substring(0,64));
//        byte[] rootPublic = Hex.decode("6ddbc4126fcb632d192d67006185b1ce77f1614db167072e0b3cae1f8824cd1a");
//        System.out.println("private:"+Hex.toHexString(rootPriv));
//        System.out.println("public:"+Hex.toHexString(rootPublic));
//        byte[] sigResult = Signer.signFn(rootPriv, "hello");
//        System.out.println("sig:"+Hex.toHexString(sigResult));
//
//        boolean result = Signer.verifyFn(rootPublic, "hello", sigResult);
//        System.out.println(result);
        //test message hello
//        String privateKey = "d343266054d9c8b175d85c755a87b77d44295c5c7e5afb56c5c2efba19d882ae6ddbc4126fcb632d192d67006185b1ce77f1614db167072e0b3cae1f8824cd1a";
//        String publicKey = "6ddbc4126fcb632d192d67006185b1ce77f1614db167072e0b3cae1f8824cd1a";
//        String message = "hello";
//        String sig = Signer.sign(privateKey, message);
        //e6f8002bd065c46ddca43dda3f8689c33729727c30dfa98c9f7fc7bbfd09764f58d01147d288303ca709ec2881b05f01a024e0c8fd9052f2cdf52504fc353101
//        System.out.println("sig:"+sig);
//        boolean res = Signer.verify(publicKey, message, sig);
//        System.out.println(res);
        //test message hello
        String privateKey = "e8dc6604ae17fcdbee1738855045f0c27a3dc1e6b94d15447a1a1bac86298a522d888be373656a46fb3f6f20b326404d4bf878cd39a126822524724260954494";
//        String publicKey = "6ddbc4126fcb632d192d67006185b1ce77f1614db167072e0b3cae1f8824cd1a";
        String message = "31b4fa69c6ab46c6523bd7863e9444697b119054c3cec734915896f5a2a13b30";
        String sig = Signer.sign(privateKey, message);
        //e6f8002bd065c46ddca43dda3f8689c33729727c30dfa98c9f7fc7bbfd09764f58d01147d288303ca709ec2881b05f01a024e0c8fd9052f2cdf52504fc353101
        System.out.println("sig:" + sig);
//        boolean res = Signer.verify(publicKey, message, sig);
//        System.out.println(res);
    }
}
