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
                "        \"raw_transaction\": \"0701dfd5c8d505010161015f0434bc790dbb3746c88fd301b9839a0f7c990bb8bdc96881d17bc2fb47525ad8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80d0dbc3f4020101160014f54622eeb837e39d359f7530b6fbbd7256c9e73d010002013effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8c98d2b0f402011600144453a011caf735428d0291d82b186e976e286fc100013afffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff40301160014613908c28df499e3aa04e033100efaa24ca8fd0100\",\n" +
                "        \"signing_instructions\": [\n" +
                "            {\n" +
                "                \"position\": 0,\n" +
                "                \"witness_components\": [\n" +
                "                    {\n" +
                "                        \"type\": \"raw_tx_signature\",\n" +
                "                        \"quorum\": 1,\n" +
                "                        \"keys\": [\n" +
                "                            {\n" +
                "                                \"xpub\": \"d9c7b41f030a398dada343096040c675be48278046623849977cb0fd01d395a51c487e8174ffc0cfa76c3be6833111a9b8cd94446e37a76ee18bb21a7d6ea66b\",\n" +
                "                                \"derivation_path\": [\n" +
                "                                    \"010400000000000000\",\n" +
                "                                    \"0100000000000000\"\n" +
                "                                ]\n" +
                "                            }\n" +
                "                        ],\n" +
                "                        \"signatures\": null\n" +
                "                    },\n" +
                "                    {\n" +
                "                        \"type\": \"data\",\n" +
                "                        \"value\": \"5024b9d7cdfe9b3ece98bc06111e06dd79d425411614bfbb473d07ca44795612\"\n" +
                "                    }\n" +
                "                ]\n" +
                "            }\n" +
                "        ],\n" +
                "        \"allow_additional_actions\": false\n" +
                "    }";
        Template template = Template.fromJson(json);
        System.out.println(template.toJson());
    }

}
