# tx_signer

## Pre

#### Get the source code

```
$ git clone https://github.com/Bytom/bytom.git $GOPATH/src/github.com/bytom
```

#### git checkout

```
$ git checkout dev-tx
```

#### Build

```
$ cd $GOPATH/src/github.com/bytom
$ make bytomd    # build bytomd
$ make bytomcli  # build bytomcli
```

When successfully building the project, the `bytom` and `bytomcli` binary should be present in `cmd/bytomd` and `cmd/bytomcli` directory, respectively.

### Initialize

First of all, initialize the node:

```
$ cd ./cmd/bytomd
$ ./bytomd init --chain_id solonet
```

### launch

```
$ ./bytomd node --mining
```

## Usage

Need 3 Parameters:

- Private Key Array
- Template Object
  - After call build transaction api return a Template json object. [build transaction api](https://github.com/Bytom/bytom/wiki/API-Reference#build-transaction)
  - use bytom java sdk return a Template object.
- Raw Transaction
  - call decode raw-transaction api. [decode raw-transaction api](https://github.com/Bytom/bytom/wiki/API-Reference#decode-raw-transaction)

Call method:

```java
// return a Template object signed offline basically.
Template result = signatures.generateSignatures(privates, template, rawTransaction);
// use result's raw_transaction call sign transaction api to build another data but not need password or private key.
```

Example:

```java
		String[] privates = new String[1];
        privates[0] = "10fdbc41a4d3b8e5a0f50dd3905c1660e7476d4db3dbd9454fa4347500a633531c487e8174ffc0cfa76c3be6833111a9b8cd94446e37a76ee18bb21a7d6ea66b";
        String raw_tx = "0701dfd5c8d505010161015f0434bc790dbb3746c88fd301b9839a0f7c990bb8bdc96881d17bc2fb47525ad8ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff80d0dbc3f4020101160014f54622eeb837e39d359f7530b6fbbd7256c9e73d010002013effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8c98d2b0f402011600144453a011caf735428d0291d82b186e976e286fc100013afffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff40301160014613908c28df499e3aa04e033100efaa24ca8fd0100";
        Client client = Client.generateClient();//http://127.0.0.1:9888
        RawTransaction rawTransaction = RawTransaction.decode(client, raw_tx);

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
        Signatures signatures = new SignaturesImpl();
        Template result = signatures.generateSignatures(privates, template, rawTransaction);
        //call sign transaction api to build another data but not need password or private key.
		
```

