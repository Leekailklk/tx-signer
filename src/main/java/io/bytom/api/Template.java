package io.bytom.api;

import com.google.gson.annotations.SerializedName;
import io.bytom.common.Utils;

import java.util.List;

public class Template {
    /**
     * A hex-encoded representation of a transaction template.
     */
    @SerializedName("raw_transaction")
    public String rawTransaction;

    /**
     * The list of signing instructions for inputs in the transaction.
     */
    @SerializedName("signing_instructions")
    public List<SigningInstruction> signingInstructions;

    /**
     * For core use only.
     */
    @SerializedName("local")
    private boolean local;

    /**
     * False (the default) makes the transaction "final" when signing, preventing
     * further changes - the signature program commits to the transaction's signature
     * hash. True makes the transaction extensible, committing only to the elements in
     * the transaction so far, permitting the addition of new elements.
     */
    @SerializedName("allow_additional_actions")
    private boolean allowAdditionalActions;

    /**
     * allowAdditionalActions causes the transaction to be signed so that it can be
     * used as a base transaction in a multiparty trade flow. To enable this setting,
     * call this method after building the transaction, but before sending it to the
     * signer.
     *
     * All participants in a multiparty trade flow should call this method except for
     * the last signer. Do not call this option if the transaction is complete, i.e.
     * if it will not be used as a base transaction.
     * @return updated transaction template
     */
    public Template allowAdditionalActions() {
        this.allowAdditionalActions = true;
        return this;
    }

    /**
     * A single signing instruction included in a transaction template.
     */
    public static class SigningInstruction {
        /**
         * The input's position in a transaction's list of inputs.
         */
        public int position;

        /**
         * A list of components used to coordinate the signing of an input.
         */
        @SerializedName("witness_components")
        public WitnessComponent[] witnessComponents;
    }

    /**
     * A single witness component, holding information that will become the input
     * witness.
     */
    public static class WitnessComponent {
        /**
         * The type of witness component.<br>
         * Possible types are "data" and "raw_tx_signature".
         */
        public String type;

        /**
         * Data to be included in the input witness (null unless type is "data").
         */
        public String value;

        /**
         * The number of signatures required for an input (null unless type is
         * "signature").
         */
        public int quorum;

        /**
         * The list of keys to sign with (null unless type is "signature").
         */
        public KeyID[] keys;

        /**
         * The list of signatures made with the specified keys (null unless type is
         * "signature").
         */
        public String[] signatures;
    }

    /**
     * A class representing a derived signing key.
     */
    public static class KeyID {
        /**
         * The extended public key associated with the private key used to sign.
         */
        public String xpub;

        /**
         * The derivation path of the extended public key.
         */
        @SerializedName("derivation_path")
        public String[] derivationPath;
    }

    /**
     * Serializes the Address into a form that is safe to transfer over the wire.
     *
     * @return the JSON-serialized representation of the Receiver object
     */
    public String toJson() {
        return Utils.serializer.toJson(this);
    }

    public static Template fromJson(String json) {
        return Utils.serializer.fromJson(json, Template.class);
    }

    public static void main(String[] args) {
        String json = "{\n" +
                "  \"allow_additional_actions\": false,\n" +
                "  \"local\": true,\n" +
                "  \"raw_transaction\": \"07010000020161015fb6a63a3361170afca03c9d5ce1f09fe510187d69545e09f95548b939cd7fffa3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80fc93afdf01000116001426bd1b851cf6eb8a701c20c184352ad8720eeee90100015d015bb6a63a3361170afca03c9d5ce1f09fe510187d69545e09f95548b939cd7fffa33152a15da72be51b330e1c0f8e1c0db669269809da4f16443ff266e07cc43680c03e0101160014489a678741ccc844f9e5c502f7fac0a665bedb25010003013effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80a2cfa5df0101160014948fb4f500e66d20fbacb903fe108ee81f9b6d9500013a3152a15da72be51b330e1c0f8e1c0db669269809da4f16443ff266e07cc43680dd3d01160014cd5a822b34e3084413506076040d508bb12232c70001393152a15da72be51b330e1c0f8e1c0db669269809da4f16443ff266e07cc436806301160014a3f9111f3b0ee96cbd119a3ea5c60058f506fb1900\",\n" +
                "  \"signing_instructions\": [\n" +
                "    {\n" +
                "      \"position\": 0,\n" +
                "      \"witness_components\": [\n" +
                "        {\n" +
                "          \"keys\": [\n" +
                "            {\n" +
                "              \"derivation_path\": [\n" +
                "                \"010100000000000000\",\n" +
                "                \"0500000000000000\"\n" +
                "              ],\n" +
                "              \"xpub\": \"ee9dd8affdef7e0cacd0fbbf310217c7f588156c28e414db74c27afaedd8f876cf54547a672b431ff06ee8a146207df9595638a041b55ada1a764a8b5b30bda0\"\n" +
                "            }\n" +
                "          ],\n" +
                "          \"quorum\": 1,\n" +
                "          \"signatures\": null,\n" +
                "          \"type\": \"raw_tx_signature\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"type\": \"data\",\n" +
                "          \"value\": \"62a73b6b7ffe52b6ad782b0e0efdc8309bf2f057d88f9a17d125e41bb11dbb88\"\n" +
                "        }\n" +
                "      ]\n" +
                "    },\n" +
                "    {\n" +
                "      \"position\": 1,\n" +
                "      \"witness_components\": [\n" +
                "        {\n" +
                "          \"keys\": [\n" +
                "            {\n" +
                "              \"derivation_path\": [\n" +
                "                \"010100000000000000\",\n" +
                "                \"0600000000000000\"\n" +
                "              ],\n" +
                "              \"xpub\": \"ee9dd8affdef7e0cacd0fbbf310217c7f588156c28e414db74c27afaedd8f876cf54547a672b431ff06ee8a146207df9595638a041b55ada1a764a8b5b30bda0\"\n" +
                "            }\n" +
                "          ],\n" +
                "          \"quorum\": 1,\n" +
                "          \"signatures\": null,\n" +
                "          \"type\": \"raw_tx_signature\"\n" +
                "        },\n" +
                "        {\n" +
                "          \"type\": \"data\",\n" +
                "          \"value\": \"ba5a63e7416caeb945eefc2ce874f40bc4aaf6005a1fc792557e41046f7e502f\"\n" +
                "        }\n" +
                "      ]\n" +
                "    }\n" +
                "  ]\n" +
                "}";
        Template template = Template.fromJson(json);
        System.out.println(template.toJson());
    }

}
