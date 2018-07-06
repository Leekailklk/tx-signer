package io.bytom.api;

public interface Signatures {

    /**
     * return signed transaction
     *
     * @param privateKeys
     * @param template
     * @param decodedTx
     * @param txID
     * @return
     */
    public Template generateSignatures(String[] privateKeys, Template template, RawTransaction decodedTx, String txID);
}
