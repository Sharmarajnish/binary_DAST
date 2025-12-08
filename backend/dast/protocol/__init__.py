"""
DAST Protocol Fuzzing Module
Automotive protocol fuzzing for UDS, CAN, and DoIP.
"""

from .boofuzz_automotive import AutomotiveProtocolFuzzer, UDSFuzzer, CANFuzzer

__all__ = [
    'AutomotiveProtocolFuzzer',
    'UDSFuzzer',
    'CANFuzzer',
]
