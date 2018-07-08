package io.bytom.common;


import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class ExpandedPrivateKeyTest {

    @Test
    public void testExpandedKey() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        byte[] z = ExpandedPrivateKey.ExpandedPrivateKey(Hex.decode("a0cde08fd2ea06e16dd5d21e64ca0609fa1d719b79fed4245a5b8ada0242464cebbc2b9e1e989aca72d9766efd9b63ebcfc968027ef27cb786babb7897f9248a"));
        System.out.println(Hex.toHexString(z));
        System.out.println(Hex.toHexString("ExpandN".getBytes()));
    }
}