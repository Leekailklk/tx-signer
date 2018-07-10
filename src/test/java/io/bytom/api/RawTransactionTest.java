package io.bytom.api;

import io.bytom.exception.BytomException;
import io.bytom.http.Client;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class RawTransactionTest {

    @Test
    public void testHashFn() throws BytomException {
        String raw_tx = "070100010161015fc8215913a270d3d953ef431626b19a89adf38e2486bb235da732f0afed515299ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8099c4d59901000116001456ac170c7965eeac1cc34928c9f464e3f88c17d8630240b1e99a3590d7db80126b273088937a87ba1e8d2f91021a2fd2c36579f7713926e8c7b46c047a43933b008ff16ecc2eb8ee888b4ca1fe3fdf082824e0b3899b02202fb851c6ed665fcd9ebc259da1461a1e284ac3b27f5e86c84164aa518648222602013effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80bbd0ec980101160014c3d320e1dc4fe787e9f13c1464e3ea5aae96a58f00013cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8084af5f01160014bb93cdb4eca74b068321eeb84ac5d33686281b6500";
        String tx_id = "4c97d7412b04d49acc33762fc748cd0780d8b44086c229c1a6d0f2adfaaac2db";
        String input_id = "9963265eb601df48501cc240e1480780e9ed6e0c8f18fd7dd57954068c5dfd02";
        Client client = Client.generateClient();
        RawTransaction decodedTx = RawTransaction.decode(client, raw_tx);

        byte[] signedHash = decodedTx.hashFn(Hex.decode(input_id), Hex.decode(tx_id));
        System.out.println("signedHash: "+Hex.toHexString(signedHash));
        // expect: 8d2bb534c819464472a94b41cea788e97a2c9dae09a6cb3b7024a44ce5a27835
        //         8d2bb534c819464472a94b41cea788e97a2c9dae09a6cb3b7024a44ce5a27835
    }

}