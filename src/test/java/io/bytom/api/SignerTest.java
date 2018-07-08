package io.bytom.api;

import com.google.crypto.tink.proto.Ed25519;
import com.google.crypto.tink.subtle.Ed25519Sign;
import io.bytom.common.ExpandedPrivateKey;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.annotation.adapters.HexBinaryAdapter;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import static org.junit.Assert.*;

public class SignerTest {

    /**
     * 产生HmacSHA256摘要算法的密钥
     */
    public static byte[] initHmacSHA512Key() throws NoSuchAlgorithmException {
        // 初始化HmacMD5摘要算法的密钥产生器
        KeyGenerator generator = KeyGenerator.getInstance("HmacSHA512");
        // 产生密钥
        SecretKey secretKey = generator.generateKey();
        // 获得密钥
        byte[] key = secretKey.getEncoded();
        System.out.println("key: "+Hex.toHexString(key));
        return key;
    }


    public static byte[] encodeHmacSHA512(byte[] data, byte[] key) throws Exception {
        // 还原密钥
        SecretKey secretKey = new SecretKeySpec(key, "HmacSHA512");
        // 实例化Mac
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        //初始化mac
        mac.init(secretKey);
        //执行消息摘要
        return mac.doFinal(data);
    }


    @Test
    public void testDeriveKey() throws Exception {
        String privateKey = "6130636465303866643265613036653136646435643231653634636130363039666131643731396237396665643432343561356238616461303234323436346365626263326239653165393839616361373264393736366566643962363365626366633936383032376566323763623738366261626237383937663932343861";
        byte[] data = new byte[]{0x45,0x78,0x70,0x61,0x6e,0x64};
        byte[] keyHmacSHA512=SignerTest.initHmacSHA512Key();
        byte[] hmacData = SignerTest.encodeHmacSHA512(data, keyHmacSHA512);
//        System.out.println("key Hmac: "+hmacData);
        byte[] hmacXPrv = SignerTest.encodeHmacSHA512(hmacData, keyHmacSHA512);
        System.out.println("hmacXPrv: "+ Hex.toHexString(hmacXPrv));

//        byte[] result = System.arraycopy(hmacXPrv,0, hmacXPrv.length/2, 0, hmacXPrv.length/2);

    }

    @Test
    public void testDeriveKeyDirect() throws NoSuchAlgorithmException, InvalidKeyException {
        String privateKey = "6130636465303866643265613036653136646435643231653634636130363039666131643731396237396665643432343561356238616461303234323436346365626263326239653165393839616361373264393736366566643962363365626366633936383032376566323763623738366261626237383937663932343861";
        byte[] prefix = new byte[]{0x45,0x78,0x70,0x61,0x6e,0x64};
        byte[] result = new byte[64];
        SecretKey secretKey = new SecretKeySpec(Hex.decode(prefix), "HmacSHA512");
        Mac mac = Mac.getInstance(secretKey.getAlgorithm());
        mac.init(secretKey);
        result = mac.doFinal(Hex.decode(privateKey));
    }

    @Test
    public void testSign() throws Exception {
        String privateKey = "e8dc6604ae17fcdbee1738855045f0c27a3dc1e6b94d15447a1a1bac86298a522d888be373656a46fb3f6f20b326404d4bf878cd39a126822524724260954494";
//        String publicKey = "6ddbc4126fcb632d192d67006185b1ce77f1614db167072e0b3cae1f8824cd1a";
        String message = "31b4fa69c6ab46c6523bd7863e9444697b119054c3cec734915896f5a2a13b30";
        String sig = Signer.sign(privateKey, message);
        //e6f8002bd065c46ddca43dda3f8689c33729727c30dfa98c9f7fc7bbfd09764f58d01147d288303ca709ec2881b05f01a024e0c8fd9052f2cdf52504fc353101
        System.out.println("sig:"+sig);
        //38ad1c69b4c266b77680f5c0ffb0b9f666690ba9dcf7d741ffcbd6971d3b0bd509ac28bb03e204a8fb0cd479fc3e4fb28e15a28fa0849658d4543d3b4bbb440c
        //38ad1c69b4c266b77680f5c0ffb0b9f666690ba9dcf7d741ffcbd6971d3b0bd509ac28bb03e204a8fb0cd479fc3e4fb28e15a28fa0849658d4543d3b4bbb440c
    }

    @Test
    public void testEd25519() throws Exception {

        String privateKey = "e8dc6604ae17fcdbee1738855045f0c27a3dc1e6b94d15447a1a1bac86298a522d888be373656a46fb3f6f20b326404d4bf878cd39a126822524724260954494";
        String message = "31b4fa69c6ab46c6523bd7863e9444697b119054c3cec734915896f5a2a13b30";
        byte[] hexPrivateKey = Hex.decode(privateKey);
        byte[] hexMessage = Hex.decode(message);

//        Ed25519Sign signer = new Ed25519Sign(Hex.decode(privateKey.substring(0, 64)));
       byte[] publicKey = com.google.crypto.tink.subtle.Ed25519.scalarMultWithBaseToBytes(Hex.decode(privateKey));
       byte[] sig = com.google.crypto.tink.subtle.Ed25519.sign(hexMessage, publicKey, hexPrivateKey);

//        byte[] sig = signer.sign(Hex.decode(message));
        System.out.println("tink sig: "+Hex.toHexString(sig));
    }

    @Test
    public void testEd25519Sign() throws GeneralSecurityException {
        String privateKey = "e8dc6604ae17fcdbee1738855045f0c27a3dc1e6b94d15447a1a1bac86298a522d888be373656a46fb3f6f20b326404d4bf878cd39a126822524724260954494";
        String message = "31b4fa69c6ab46c6523bd7863e9444697b119054c3cec734915896f5a2a13b30";
        byte[] hexPrivateKey = Hex.decode(privateKey);
        byte[] hexMessage = Hex.decode(message);

        Ed25519Sign signer = new Ed25519Sign(Hex.decode(privateKey.substring(0, 64)));

        byte[] sig = signer.sign(Hex.decode(message));
        System.out.println("tink sig: "+Hex.toHexString(sig));
    }

    @Test
    public void testEd25519SignPublicPrivate() throws GeneralSecurityException {
        String privateKey = "e8c0965af60563c4cabcf2e947b1cd955c4f501eb946ffc8c3447e5ec8a6335398a3720b3f96077fa187fdde48fe7dc293984b196f5e292ef8ed78fdbd8ed954";
        String publicKey = "d9c7b41f030a398dada343096040c675be48278046623849977cb0fd01d395a51c487e8174ffc0cfa76c3be6833111a9b8cd94446e37a76ee18bb21a7d6ea66b";
        String message = "02eda3cd8d1b0efaf7382af6ea53a429ed3ed6042998d2b4a382575248ebc922";
        byte[] hexPrivateKey = Hex.decode(privateKey);
        byte[] expandedPrv = ExpandedPrivateKey.ExpandedPrivateKey(hexPrivateKey);
        System.out.println("offline expandedKey: "+Hex.toHexString(expandedPrv));

        byte[] hexPublicKey = Hex.decode(publicKey);
        byte[] hexMessage = Hex.decode(message);

        byte[] sig = com.google.crypto.tink.subtle.Ed25519.sign(hexMessage, hexPublicKey, expandedPrv);

        System.out.println("tink sig: "+Hex.toHexString(sig));
    }

}