from micropython import const

from trezor import wire
from trezor.crypto.hashlib import blake256
from trezor.messages import InputScriptType, OutputScriptType
from trezor.messages.PrevOutput import PrevOutput
from trezor.messages.SignTx import SignTx
from trezor.utils import HashWriter, ensure

from apps.common.writers import write_bitcoin_varint

from .. import addresses, common, multisig, scripts, writers
from ..common import ecdsa_hash_pubkey, ecdsa_sign
from . import approvers, helpers, progress
from .bitcoin import Bitcoin

DECRED_SERIALIZE_FULL = const(0 << 16)
DECRED_SERIALIZE_NO_WITNESS = const(1 << 16)
DECRED_SERIALIZE_WITNESS_SIGNING = const(3 << 16)
DECRED_SCRIPT_VERSION = const(0)

DECRED_SIGHASH_ALL = const(1)

if False:
    from typing import Union

    from trezor.messages.TxInput import TxInput
    from trezor.messages.TxOutput import TxOutput
    from trezor.messages.PrevTx import PrevTx
    from trezor.messages.PrevInput import PrevInput

    from apps.common.coininfo import CoinInfo
    from apps.common.keychain import Keychain


class Decred(Bitcoin):
    def __init__(
        self,
        tx: SignTx,
        keychain: Keychain,
        coin: CoinInfo,
        approver: approvers.Approver,
    ) -> None:
        ensure(coin.decred)
        super().__init__(tx, keychain, coin, approver)

        self.write_tx_header(self.serialized_tx, self.tx, witness_marker=True)
        write_bitcoin_varint(self.serialized_tx, self.tx.inputs_count)

    def init_hash143(self) -> None:
        self.h_prefix = self.create_hash_writer()
        writers.write_uint32(
            self.h_prefix, self.tx.version | DECRED_SERIALIZE_NO_WITNESS
        )
        write_bitcoin_varint(self.h_prefix, self.tx.inputs_count)

    def create_hash_writer(self) -> HashWriter:
        return HashWriter(blake256())

    async def step2_approve_outputs(self) -> None:
        write_bitcoin_varint(self.serialized_tx, self.tx.outputs_count)
        write_bitcoin_varint(self.h_prefix, self.tx.outputs_count)
        for i in range(self.tx.outputs_count):
            # STAGE_REQUEST_3_OUTPUT in legacy
            txo = await helpers.request_tx_output(self.tx_req, i, self.coin)
            script_pubkey = self.output_derive_script(txo)
            await self.approve_output(txo, script_pubkey)
        self.write_tx_footer(self.serialized_tx, self.tx)
        self.write_tx_footer(self.h_prefix, self.tx)

    async def process_internal_input(self, txi: TxInput) -> None:
        await super().process_internal_input(txi)

        # Decred serializes inputs early.
        self.write_tx_input(self.serialized_tx, txi, bytes())

    async def process_external_input(self, txi: TxInput) -> None:
        raise wire.DataError("External inputs not supported")

    async def approve_output(self, txo: TxOutput, script_pubkey: bytes) -> None:
        if self.output_is_change(txo):
            # output is change and does not need approval
            self.approver.add_change_output(txo, script_pubkey)
        else:
            await self.approver.add_external_output(txo, script_pubkey)

        self.write_tx_output(self.h_approved, txo, script_pubkey)
        self.hash143_add_output(txo, script_pubkey)
        self.write_tx_output(self.serialized_tx, txo, script_pubkey)

    def output_is_change(self, txo: TxOutput) -> bool:
        if txo.script_type == OutputScriptType.SSTXCHANGE:
            return True
        return super().output_is_change(txo)

    async def step4_serialize_inputs(self) -> None:
        write_bitcoin_varint(self.serialized_tx, self.tx.inputs_count)

        prefix_hash = self.h_prefix.get_digest()

        for i_sign in range(self.tx.inputs_count):
            progress.advance()

            txi_sign = await helpers.request_tx_input(self.tx_req, i_sign, self.coin)

            self.wallet_path.check_input(txi_sign)
            self.multisig_fingerprint.check_input(txi_sign)

            key_sign = self.keychain.derive(txi_sign.address_n)
            key_sign_pub = key_sign.public_key()

            if txi_sign.script_type == InputScriptType.SPENDMULTISIG:
                assert txi_sign.multisig is not None
                prev_pkscript = scripts.output_script_multisig(
                    multisig.multisig_get_pubkeys(txi_sign.multisig),
                    txi_sign.multisig.m,
                )
            elif txi_sign.script_type == InputScriptType.SPENDADDRESS:
                prev_pkscript = scripts.output_script_p2pkh(
                    ecdsa_hash_pubkey(key_sign_pub, self.coin)
                )
            elif txi_sign.script_type == InputScriptType.SPENDSSRTX:
                prev_pkscript = scripts.input_script_ssrtx(
                    ecdsa_hash_pubkey(key_sign_pub, self.coin)
                )
            elif txi_sign.script_type == InputScriptType.SPENDSSGEN:
                prev_pkscript = scripts.input_script_ssgen(
                    ecdsa_hash_pubkey(key_sign_pub, self.coin)
                )
            else:
                raise wire.DataError("Unsupported input script type")

            h_witness = self.create_hash_writer()
            writers.write_uint32(
                h_witness, self.tx.version | DECRED_SERIALIZE_WITNESS_SIGNING
            )
            write_bitcoin_varint(h_witness, self.tx.inputs_count)

            for ii in range(self.tx.inputs_count):
                if ii == i_sign:
                    writers.write_bytes_prefixed(h_witness, prev_pkscript)
                else:
                    write_bitcoin_varint(h_witness, 0)

            witness_hash = writers.get_tx_hash(
                h_witness, double=self.coin.sign_hash_double, reverse=False
            )

            h_sign = self.create_hash_writer()
            writers.write_uint32(h_sign, DECRED_SIGHASH_ALL)
            writers.write_bytes_fixed(h_sign, prefix_hash, writers.TX_HASH_SIZE)
            writers.write_bytes_fixed(h_sign, witness_hash, writers.TX_HASH_SIZE)

            sig_hash = writers.get_tx_hash(h_sign, double=self.coin.sign_hash_double)
            signature = ecdsa_sign(key_sign, sig_hash)

            # serialize input with correct signature
            script_sig = self.input_derive_script(txi_sign, key_sign_pub, signature)
            self.write_tx_input_witness(self.serialized_tx, txi_sign, script_sig)
            self.set_serialized_signature(i_sign, signature)

    async def step5_serialize_outputs(self) -> None:
        pass

    async def step6_sign_segwit_inputs(self) -> None:
        pass

    async def step7_finish(self) -> None:
        await helpers.request_tx_finish(self.tx_req)

    def check_prevtx_output(self, txo_bin: PrevOutput) -> None:
        if txo_bin.decred_script_version != 0:
            raise wire.ProcessError("Cannot use utxo that has script_version != 0")

    def hash143_add_input(self, txi: TxInput) -> None:
        self.write_tx_input(self.h_prefix, txi, bytes())

    def hash143_add_output(self, txo: TxOutput, script_pubkey: bytes) -> None:
        self.write_tx_output(self.h_prefix, txo, script_pubkey)

    def write_tx_input(
        self, w: writers.Writer, txi: Union[TxInput, PrevInput], script: bytes,
    ) -> None:
        writers.write_bytes_reversed(w, txi.prev_hash, writers.TX_HASH_SIZE)
        writers.write_uint32(w, txi.prev_index or 0)
        writers.write_uint8(w, txi.decred_tree or 0)
        writers.write_uint32(w, txi.sequence)

    def write_tx_output(
        self, w: writers.Writer, txo: Union[TxOutput, PrevOutput], script_pubkey: bytes,
    ) -> None:
        writers.write_uint64(w, txo.amount)
        if isinstance(txo, PrevOutput):
            if txo.decred_script_version is None:
                raise wire.DataError("Script version must be provided")
            writers.write_uint16(w, txo.decred_script_version)
        else:
            writers.write_uint16(w, DECRED_SCRIPT_VERSION)
        writers.write_bytes_prefixed(w, script_pubkey)

    def write_tx_header(
        self, w: writers.Writer, tx: Union[SignTx, PrevTx], witness_marker: bool,
    ) -> None:
        # The upper 16 bits of the transaction version specify the serialization
        # format and the lower 16 bits specify the version number.
        if witness_marker:
            version = tx.version | DECRED_SERIALIZE_FULL
        else:
            version = tx.version | DECRED_SERIALIZE_NO_WITNESS

        writers.write_uint32(w, version)

    def write_tx_footer(self, w: writers.Writer, tx: Union[SignTx, PrevTx]) -> None:
        assert tx.expiry is not None  # checked in sanitize_*
        writers.write_uint32(w, tx.lock_time)
        writers.write_uint32(w, tx.expiry)

    def write_tx_input_witness(
        self, w: writers.Writer, i: TxInput, script_sig: bytes
    ) -> None:
        writers.write_uint64(w, i.amount)
        writers.write_uint32(w, 0)  # block height fraud proof
        writers.write_uint32(w, 0xFFFFFFFF)  # block index fraud proof
        writers.write_bytes_prefixed(w, script_sig)

    def output_derive_script(self, txo: TxOutput) -> bytes:
        if txo.script_type == OutputScriptType.PAYTOOPRETURN:
            assert txo.op_return_data is not None  # checked in sanitize_tx_output
            return scripts.output_script_paytoopreturn(txo.op_return_data)
        elif txo.script_type == OutputScriptType.SSTXSUBMISSIONPKH:
            assert txo.address is not None  # checked in sanitize_tx_output
            return scripts.output_script_sstxsubmissionpkh(txo.address)
        elif txo.script_type == OutputScriptType.SSTXSUBMISSIONSH:
            assert txo.address is not None  # checked in sanitize_tx_output
            return scripts.output_script_sstxsubmissionsh(txo.address)
        elif txo.script_type == OutputScriptType.SSTXCHANGE:
            assert txo.address is not None  # checked in sanitize_tx_output
            # Change addresses are not currently used. Inputs should be exact.
            if txo.amount != 0:
                raise wire.DataError("Only value of 0 allowed for sstx change")
            return scripts.output_script_sstxchange(txo.address)

        if txo.address_n:
            # change output
            try:
                input_script_type = common.CHANGE_OUTPUT_TO_INPUT_SCRIPT_TYPES[
                    txo.script_type
                ]
            except KeyError:
                raise wire.DataError("Invalid script type")
            node = self.keychain.derive(txo.address_n)
            txo.address = addresses.get_address(
                input_script_type, self.coin, node, txo.multisig
            )

        assert txo.address is not None  # checked in sanitize_tx_output

        return scripts.output_derive_script(txo.address, self.coin)
