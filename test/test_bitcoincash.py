from unittest import TestCase
import bitcoin


class TestBitcoinCash(TestCase):
    def test_bitcoincash_p2pkh(self):
        priv1 = bitcoin.encode_privkey(bitcoin.sha256('1'), 'hex_compressed')
        vin = ['b8c191ca7f414eed8a6a4bf343d0e494e74b61a50b1c801fdddc56be7bf10407', 1, 12]
        tx = bitcoin.mktx(
            [
                {
                    'output': '{}:{}'.format(vin[0], vin[1]),
                    'amount': vin[2]
                }
            ],
            [
                {
                    "value": int(12 * 10 ** 8) - 100000,
                    "address": "mtQ6C2A8hVabXxzskNatUNCe7A8qaqEG73"
                }
            ]
        )
        signed = bitcoin.segwit_sign(
            tx, 0, priv1, vin[2] * 10 ** 8, hashcode=bitcoin.SIGHASH_ALL | bitcoin.SIGHASH_FORKID, separator_index=None
        )
        assert signed == '01000000010704f17bbe56dcdd1f801c0ba5614be794e4d043f34b6a8aed4e417fca91c1b8010000006b4830450' \
                         '22100e63e3d7f4338b8e7e266a7c435ef1178e088f55fd12fb10036d92de473c622bd0220390f38c51a84a09d52' \
                         '0d9a8aa9b7bf40bdb49c29ccc551ae6d518a56c106d76f412103fdf4907810a9f5d9462a1ae09feee5ab205d327' \
                         '98b0ffcc379442021f84c5bbfffffffff0160058547000000001976a9148d4d508f5bf2c28b20a3863405f05d3c' \
                         'd374b04588ac00000000'
        print('[BitcoinCash] Testing BitcoinCash P2PKH Single Signature')


    def test_bitcoincash_multisig(self):
        priv1 = bitcoin.encode_privkey(bitcoin.sha256('1'), 'hex_compressed')
        priv2 = bitcoin.encode_privkey(bitcoin.sha256('2'), 'hex_compressed')
        priv3 = bitcoin.encode_privkey(bitcoin.sha256('3'), 'hex_compressed')
        pub1 = bitcoin.privtopub(priv1)
        pub2 = bitcoin.privtopub(priv2)
        pub3 = bitcoin.privtopub(priv3)
        script = bitcoin.mk_multisig_script([pub1, pub2, pub3], 2)
        vin = ['8bd1c2b6dd6a35da9f7308e47bd79c85ffc194d844c2fd354476dde8ab05eccd', 0, 10]
        tx = bitcoin.mktx(
            [
                {
                    'output': '{}:{}'.format(vin[0], vin[1]),
                    'amount': vin[2]
                }
            ],
            [
                {
                    "value": int(10 * 10 ** 8) - 100000,
                    "address": "n1ww222Y8uZzCz1Havrb8eYkqrXEnNCaJe"
                }
            ]
        )
        signature1 = bitcoin.segwit_multisign(
            tx, 0, script, priv1, vin[2] * 10 ** 8,
            hashcode=bitcoin.SIGHASH_ALL | bitcoin.SIGHASH_FORKID, separator_index=None
        )
        signature2 = bitcoin.segwit_multisign(
            tx, 0, script, priv2, vin[2] * 10 ** 8,
            hashcode=bitcoin.SIGHASH_ALL | bitcoin.SIGHASH_FORKID, separator_index=None
        )
        partially_signed = bitcoin.apply_multisignatures(tx, 0, script, [signature1])
        signed = bitcoin.apply_multisignatures(tx, 0, script, [signature1, signature2])
        bitcoinjs_wif = 'cRBid6zSdoWE99SGL427daYjU3d6G8QWwLnvwgwYcmgKcrYBM2pL'
        hexkey = bitcoin.encode_privkey(bitcoin.decode_privkey(bitcoinjs_wif), 'hex_compressed')
        assert hexkey == priv1
        expected_partial = '0100000001cdec05abe8dd764435fdc244d894c1ff859cd77be408739fda356addb6c2d18b00000' \
                           '000b40047304402206ddb76e799b232d26a3404de441571803104973fbadc3403c5710ff51ef1c4' \
                           'b50220359b13fd5e886cbae49ac2fa782d8138b99235c7745bc3683559dfda2d356d9d414c69522' \
                           '103fdf4907810a9f5d9462a1ae09feee5ab205d32798b0ffcc379442021f84c5bbf21039ebd374e' \
                           'ea3befddf46bbb182e291fb719ee1b705b0b7802161038eb7da8a0362102b0915b333926d5338ca' \
                           'dba614164c99be83592a13d8bdecb6f679593c11b79d853aeffffffff016043993b000000001976' \
                           'a914e01bd9636af7e8df8c96a5fc5c0025966672785b88ac00000000'
        assert partially_signed == expected_partial
        verified = bitcoin.segwit_verify_tx_input(
            partially_signed,
            0,
            script,
            signature1,
            pub1,
            vin[2] * 10 ** 8
        )
        assert verified
        assert signed == '0100000001cdec05abe8dd764435fdc244d894c1ff859cd77be408739fda356addb6c2d18b00000000fd' \
                         'fd000047304402206ddb76e799b232d26a3404de441571803104973fbadc3403c5710ff51ef1c4b50220' \
                         '359b13fd5e886cbae49ac2fa782d8138b99235c7745bc3683559dfda2d356d9d41483045022100c4ba6b' \
                         'ae38a4f86f64232b607b41b66a307697fa5e39a63c00771d9550c5ffba02205c64973473eaa476ed1e75' \
                         '888f14ec4028f97c819e8c4d456aec66ba265bd04b414c69522103fdf4907810a9f5d9462a1ae09feee5' \
                         'ab205d32798b0ffcc379442021f84c5bbf21039ebd374eea3befddf46bbb182e291fb719ee1b705b0b78' \
                         '02161038eb7da8a0362102b0915b333926d5338cadba614164c99be83592a13d8bdecb6f679593c11b79' \
                         'd853aeffffffff016043993b000000001976a914e01bd9636af7e8df8c96a5fc5c0025966672785b88ac' \
                         '00000000'
        print('[BitcoinCash] Testing BitcoinCash 2-on-3 P2SH Multisignature')