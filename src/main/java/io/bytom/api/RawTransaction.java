package io.bytom.api;

import com.google.gson.annotations.SerializedName;
import io.bytom.common.Utils;
import io.bytom.exception.BytomException;
import io.bytom.http.Client;
import org.apache.log4j.Logger;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.jcajce.provider.digest.SHA3;
import org.bouncycastle.jcajce.provider.digest.SHA3.DigestSHA3;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.encoders.HexEncoder;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class RawTransaction {
    /**
     * version
     */
    public Integer version;
    /**
     * size
     */
    public Integer size;
    /**
     * time_range
     */
    @SerializedName("time_range")
    public Integer timeRange;

    /**
     * status
     */
    public Integer fee;

    /**
     * List of specified inputs for a transaction.
     */
    public List<AnnotatedInput> inputs;

    /**
     * List of specified outputs for a transaction.
     */
    public List<AnnotatedOutput> outputs;

    private static Logger logger = Logger.getLogger(RawTransaction.class);

    public String toJson() {
        return Utils.serializer.toJson(this);
    }

    public static RawTransaction decode(Client client, String txId) throws BytomException {
        Map<String, Object> req = new HashMap<String, Object>();
        req.put("raw_transaction", txId);
        RawTransaction rawTransaction =
                client.request("decode-raw-transaction", req, RawTransaction.class);

        logger.info("decode-raw-transaction:");
        logger.info(rawTransaction.toJson());

        return rawTransaction;
    }

    public static class AnnotatedInput {

        /**
         * address
         */
        private String address;

        /**
         * The number of units of the asset being issued or spent.
         */
        private long amount;

        /**
         * The definition of the asset being issued or spent (possibly null).
         */
        @SerializedName("asset_definition")
        private Map<String, Object> assetDefinition;

        /**
         * The id of the asset being issued or spent.
         */
        @SerializedName("asset_id")
        private String assetId;

        /**
         * The control program which must be satisfied to transfer this output.
         */
        @SerializedName("control_program")
        private String controlProgram;

        /**
         * The id of the output consumed by this input. Null if the input is an
         * issuance.
         */
        @SerializedName("spent_output_id")
        private String spentOutputId;

        /**
         * The type of the input.<br>
         * Possible values are "issue" and "spend".
         */
        private String type;

        @Override
        public String toString() {
            return Utils.serializer.toJson(this);
        }

    }

    public static class AnnotatedOutput {

        /**
         * address
         */
        private String address;

        /**
         * The number of units of the asset being controlled.
         */
        private long amount;

        /**
         * The definition of the asset being controlled (possibly null).
         */
        @SerializedName("asset_definition")
        private Map<String, Object> assetDefinition;

        /**
         * The id of the asset being controlled.
         */
        @SerializedName("asset_id")
        public String assetId;

        /**
         * The control program which must be satisfied to transfer this output.
         */
        @SerializedName("control_program")
        private String controlProgram;

        /**
         * The id of the output.
         */
        @SerializedName("id")
        private String id;

        /**
         * The output's position in a transaction's list of outputs.
         */
        private Integer position;

        /**
         * The type the output.<br>
         * Possible values are "control" and "retire".
         */
        private String type;

    }

    /**
     * Get SHA-256 hash.
     */
    public static byte[] sha256(byte[] input) {
        Digest d = new SHA256Digest();
        d.update(input, 0, input.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    public byte[] sigHash(int index, String txID) {
        Digest d = new SHA256Digest();
        byte[] input = Hex.decode("9963265eb601df48501cc240e1480780e9ed6e0c8f18fd7dd57954068c5dfd02");
        System.out.println("input: "+Hex.toHexString(input));
        // input hash
        d.update(input, 0, input.length);
        byte[] txID_byte = Hex.decode(txID);
        System.out.println("tx_id: "+Hex.toHexString(txID_byte));
        // tx_id hash
        d.update(txID_byte, 0, txID_byte.length);
        byte[] out = new byte[d.getDigestSize()];
        d.doFinal(out, 0);
        return out;
    }

    public byte[] signShA3Hash(String hashedInputHex, String txID) {
        SHA3.Digest256 digest256 = new SHA3.Digest256();
        byte[] temp = Hex.decode(hashedInputHex+txID);
        byte[] result = digest256.digest(temp);
        return result;
    }

    public static void main(String[] args) throws BytomException {
//        byte[] temp = RawTransaction.sha256("hello".getBytes());
//        System.out.println("origin:"+Hex.toHexString("hello".getBytes()));
//        System.out.println("sha256:"+Hex.toHexString(temp));
        String raw_tx = "070100010161015fc8215913a270d3d953ef431626b19a89adf38e2486bb235da732f0afed515299ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8099c4d59901000116001456ac170c7965eeac1cc34928c9f464e3f88c17d8630240b1e99a3590d7db80126b273088937a87ba1e8d2f91021a2fd2c36579f7713926e8c7b46c047a43933b008ff16ecc2eb8ee888b4ca1fe3fdf082824e0b3899b02202fb851c6ed665fcd9ebc259da1461a1e284ac3b27f5e86c84164aa518648222602013effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80bbd0ec980101160014c3d320e1dc4fe787e9f13c1464e3ea5aae96a58f00013cffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8084af5f01160014bb93cdb4eca74b068321eeb84ac5d33686281b6500";
        String tx_id = "4c97d7412b04d49acc33762fc748cd0780d8b44086c229c1a6d0f2adfaaac2db";
        String input = "9963265eb601df48501cc240e1480780e9ed6e0c8f18fd7dd57954068c5dfd02";
        Client client = Client.generateClient();
        RawTransaction rawTransaction = RawTransaction.decode(client, raw_tx);
//        byte[] signedHash = rawTransaction.sigHash(rawTransaction.inputs.size()-1, tx_id);
        byte[] signedHash = rawTransaction.signShA3Hash(input, tx_id);
        System.out.println("signedHash: "+Hex.toHexString(signedHash));
    }



}
