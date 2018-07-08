package io.bytom.common;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;


public class NonHardenedChildTest {

    @Test
    public void testChild() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        String hxprv = "28c1fb11f4cfc59417175fdb5e147a6475af0320664b5cd10daf799e67268a522c42a052a728cdaddcb453785d06e54b0ffc8775b46eb320ad96e046e69ad288";
        String hxpub = "ba15a4690a34e0a6f8aeabadcbdee0442d76143de0a868a9e47fa386fd86a1302c42a052a728cdaddcb453785d06e54b0ffc8775b46eb320ad96e046e69ad288";
        String[] hpaths = {"010300000000000000", "0100000000000000"};
        String res = hxprv;
        for (int i = 0; i < hpaths.length; i++) {
            byte[] resByte = NonHardenedChild.child(hpaths[i], res, hxpub);
            res = Hex.toHexString(resByte);
        }
        System.out.println("res: "+res);
    }

}