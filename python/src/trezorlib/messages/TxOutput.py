# Automatically generated by pb2py
# fmt: off
from .. import protobuf as p

from .MultisigRedeemScriptType import MultisigRedeemScriptType

if __debug__:
    try:
        from typing import Dict, List  # noqa: F401
        from typing_extensions import Literal  # noqa: F401
        EnumTypeOutputScriptType = Literal[0, 1, 2, 3, 4, 5, 6, 7, 8]
    except ImportError:
        pass


class TxOutput(p.MessageType):

    def __init__(
        self,
        *,
        amount: int,
        address_n: List[int] = None,
        address: str = None,
        script_type: EnumTypeOutputScriptType = 0,
        multisig: MultisigRedeemScriptType = None,
        op_return_data: bytes = None,
    ) -> None:
        self.address_n = address_n if address_n is not None else []
        self.amount = amount
        self.address = address
        self.script_type = script_type
        self.multisig = multisig
        self.op_return_data = op_return_data

    @classmethod
    def get_fields(cls) -> Dict:
        return {
            1: ('address', p.UnicodeType, None),
            2: ('address_n', p.UVarintType, p.FLAG_REPEATED),
            3: ('amount', p.UVarintType, p.FLAG_REQUIRED),
            4: ('script_type', p.EnumType("OutputScriptType", (0, 1, 2, 3, 4, 5, 6, 7, 8)), 0),  # default=PAYTOADDRESS
            5: ('multisig', MultisigRedeemScriptType, None),
            6: ('op_return_data', p.BytesType, None),
        }
