package io.bytom.api;

import io.bytom.common.ExpandedPrivateKey;
import org.bouncycastle.util.encoders.Hex;

public class SignaturesImpl implements Signatures {
    @Override
    public Template generateSignatures(String[] privateKeys, Template template, RawTransaction decodedTx) {
        Template result = template;
        for (int i = 0; i < template.signingInstructions.size(); i++) {
            Template.SigningInstruction sigIns = template.signingInstructions.get(i);
            for (Template.WitnessComponent wc : sigIns.witnessComponents) {
                // Have two cases
                switch (wc.type) {
                    case "raw_tx_signature":
                        System.out.println(wc.keys.length);
                        if (wc.signatures==null || wc.signatures.length < wc.keys.length) {
                            wc.signatures = new String[wc.keys.length];
                        }
                        for (int j = 0; j < wc.keys.length; j++) {
                            if (wc.signatures[j] == null || wc.signatures[j].isEmpty()) {
                                //byte[] sigBytes = Signer.signFn(Hex.decode(privateKeys[j]), decodedTx.sigHash(i, txID).toString());
                                String input = decodedTx.inputs.get(j).inputID;
                                String tx_id = decodedTx.txID;
                                byte[] message = decodedTx.hashFn(Hex.decode(input), Hex.decode(tx_id));
                                String output = privateKeys[j];
                                System.out.println("privateKeys[j]: "+output);
                                byte[] sig = new byte[64];
                                try {
                                    //d62fa1868b9b00ac40026e19ba094d011a323ce4d1356cc3d775927ec432ae41d25398bc65c39e688fcabab7109eb85a8c5e71ebf37e319dcb6c10f84fbf1408
//                                    sig = Signer.sign(privateKeys[j], Hex.toHexString(message));
                                    String publicKey = wc.keys[j].xpub;
                                    byte[] hexPublicKey = Hex.decode(publicKey);
                                    byte[] privateKey = Hex.decode(privateKeys[j]);
                                    byte[] expandedPrv = ExpandedPrivateKey.ExpandedPrivateKey(privateKey);
                                    System.out.println("publicKey: "+publicKey);
                                    System.out.println("privateKey: "+Hex.toHexString(expandedPrv));
                                    System.out.println("message: "+Hex.toHexString(message));
                                    sig = com.google.crypto.tink.subtle.Ed25519.sign(message, hexPublicKey, expandedPrv);
                                    System.out.println("sig google: "+Hex.toHexString(sig));

                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                System.out.println("sig:"+Hex.toHexString(sig));
                                wc.signatures[j] = Hex.toHexString(sig);
                                template.signingInstructions.get(i).witnessComponents[j].signatures = wc.signatures;
                            }

                        }
                        break;
                    case "":

                        break;
                    default:

                }
            }
        }
        return template;
    }



}
