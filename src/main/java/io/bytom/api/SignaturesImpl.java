package io.bytom.api;

import org.bouncycastle.util.encoders.Hex;

import java.security.MessageDigest;
import java.util.Arrays;

public class SignaturesImpl implements Signatures {
    @Override
    public Template generateSignatures(String[] privateKeys, Template template, RawTransaction decodedTx, String txID) {
        Template result = template;
        for (int i = 0; i < template.signingInstructions.size(); i++) {
            Template.SigningInstruction sigIns = template.signingInstructions.get(i);
            for (Template.WitnessComponent wc : sigIns.witnessComponents) {
                // Have two cases
                switch (wc.type) {
                    case "raw_tx_signature":
                        if (wc.signatures.length < wc.keys.length) {
                            wc.signatures = new String[wc.keys.length];
                        }
                        for (int j = 0; j < wc.keys.length; j++) {
                            if (wc.signatures[j] != null && wc.signatures[j].isEmpty()) {
                                byte[] sigBytes = Signer.signFn(Hex.decode(privateKeys[j]), decodedTx.sigHash(i, txID).toString());
                                wc.signatures[j] = Hex.toHexString(sigBytes);
                            }

                        }
                        break;
                    case "":

                        break;
                    default:

                }
            }
        }
        return result;
    }



}
