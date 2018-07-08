package io.bytom.api;

import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.util.Arrays;

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
                                //8d2bb534c819464472a94b41cea788e97a2c9dae09a6cb3b7024a44ce5a27835
                                String hexMessage = Hex.toHexString(message);
                                System.out.println("hexMessage: "+hexMessage);
                                //d343266054d9c8b175d85c755a87b77d44295c5c7e5afb56c5c2efba19d882ae6ddbc4126fcb632d192d67006185b1ce77f1614db167072e0b3cae1f8824cd1a
                                String output = privateKeys[j];
                                System.out.println("privateKeys[j]: "+output);
                                String sig = null;
                                try {
                                    //d62fa1868b9b00ac40026e19ba094d011a323ce4d1356cc3d775927ec432ae41d25398bc65c39e688fcabab7109eb85a8c5e71ebf37e319dcb6c10f84fbf1408
                                    sig = Signer.sign(privateKeys[j], Hex.toHexString(message));
                                } catch (Exception e) {
                                    e.printStackTrace();
                                }
                                System.out.println("sig:"+sig);
                                wc.signatures[j] = sig;
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
