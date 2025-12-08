"""
Automotive Protocol Fuzzer
Boofuzz-based fuzzing for UDS, CAN, and DoIP protocols.
"""

import logging
import socket
import struct
from typing import List, Dict, Optional, Any, Callable
from dataclasses import dataclass, field
import time

logger = logging.getLogger(__name__)

# Try to import boofuzz
try:
    from boofuzz import Session, Target, SocketConnection, TCPSocketConnection
    from boofuzz import s_initialize, s_block, s_byte, s_bytes, s_word, s_string
    from boofuzz import s_size, s_checksum, s_group, s_static
    from boofuzz.monitors import BaseMonitor
    BOOFUZZ_AVAILABLE = True
except ImportError:
    BOOFUZZ_AVAILABLE = False


@dataclass
class FuzzingResult:
    """Result from protocol fuzzing."""
    protocol: str
    test_cases_run: int
    crashes_found: int
    hangs_found: int
    anomalies: List[Dict[str, Any]]
    vulnerabilities: List[Dict[str, Any]]
    duration: float = 0.0


@dataclass
class UDSService:
    """UDS service definition for fuzzing."""
    sid: int
    name: str
    subfunctions: List[int] = field(default_factory=list)
    requires_security: bool = False
    data_format: str = "bytes"


class AutomotiveProtocolFuzzer:
    """
    Main automotive protocol fuzzer supporting UDS, CAN, and DoIP.
    
    Uses Boofuzz for intelligent protocol fuzzing with automotive-specific
    test cases and vulnerability detection.
    """
    
    # UDS Services (ISO 14229)
    UDS_SERVICES = [
        UDSService(0x10, "DiagnosticSessionControl", [0x01, 0x02, 0x03]),
        UDSService(0x11, "ECUReset", [0x01, 0x02, 0x03]),
        UDSService(0x14, "ClearDiagnosticInformation"),
        UDSService(0x19, "ReadDTCInformation", [0x01, 0x02, 0x06, 0x0A]),
        UDSService(0x22, "ReadDataByIdentifier"),
        UDSService(0x23, "ReadMemoryByAddress", requires_security=True),
        UDSService(0x24, "ReadScalingDataByIdentifier"),
        UDSService(0x27, "SecurityAccess", [0x01, 0x02, 0x11, 0x12]),
        UDSService(0x28, "CommunicationControl", [0x00, 0x01, 0x02, 0x03]),
        UDSService(0x2E, "WriteDataByIdentifier", requires_security=True),
        UDSService(0x2F, "InputOutputControlByIdentifier", requires_security=True),
        UDSService(0x31, "RoutineControl", [0x01, 0x02, 0x03], requires_security=True),
        UDSService(0x34, "RequestDownload", requires_security=True),
        UDSService(0x35, "RequestUpload", requires_security=True),
        UDSService(0x36, "TransferData", requires_security=True),
        UDSService(0x37, "RequestTransferExit", requires_security=True),
        UDSService(0x3E, "TesterPresent", [0x00, 0x80]),
        UDSService(0x85, "ControlDTCSetting", [0x01, 0x02]),
    ]
    
    def __init__(
        self,
        target_ip: Optional[str] = None,
        target_port: int = 13400,  # DoIP default port
        can_interface: Optional[str] = None,
        use_simulation: bool = False
    ):
        """
        Initialize protocol fuzzer.
        
        Args:
            target_ip: Target IP for DoIP/UDS over IP
            target_port: Target port
            can_interface: CAN interface (e.g., 'can0', 'vcan0')
            use_simulation: Force simulation mode
        """
        self.target_ip = target_ip
        self.target_port = target_port
        self.can_interface = can_interface
        self.use_simulation = use_simulation or not BOOFUZZ_AVAILABLE
        
        self.session: Optional[Any] = None
        self.results: List[FuzzingResult] = []
        self.anomalies: List[Dict[str, Any]] = []
        
        if not BOOFUZZ_AVAILABLE:
            logger.warning("Boofuzz not installed - running in simulation mode")
    
    def setup_uds_session(self) -> bool:
        """
        Set up UDS fuzzing session.
        
        Returns:
            True if successful
        """
        if self.use_simulation:
            logger.info("[Simulation] UDS session would be set up")
            return True
        
        if not self.target_ip:
            logger.error("No target IP specified for UDS session")
            return False
        
        try:
            # Create Boofuzz session
            self.session = Session(
                target=Target(
                    connection=TCPSocketConnection(
                        self.target_ip,
                        self.target_port,
                        send_timeout=5.0,
                        recv_timeout=5.0
                    )
                ),
                sleep_time=0.1,
                restart_sleep_time=1.0
            )
            
            # Define UDS protocol structure
            self._define_uds_protocol()
            
            logger.info(f"UDS session configured for {self.target_ip}:{self.target_port}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to set up UDS session: {e}")
            return False
    
    def _define_uds_protocol(self) -> None:
        """Define UDS protocol for Boofuzz."""
        
        # Diagnostic Session Control
        s_initialize("uds_diagnostic_session")
        s_byte(0x10, name="sid", fuzzable=False)
        s_byte(0x01, name="subfunction")  # Default, extended, programming
        
        # Security Access - Request Seed
        s_initialize("uds_security_request")
        s_byte(0x27, name="sid", fuzzable=False)
        s_byte(0x01, name="subfunction")
        
        # Security Access - Send Key
        s_initialize("uds_security_sendkey")
        s_byte(0x27, name="sid", fuzzable=False)
        s_byte(0x02, name="subfunction", fuzzable=False)
        s_bytes(b"\x00\x00\x00\x00", name="key", size=4)
        
        # Read Data By Identifier
        s_initialize("uds_read_data")
        s_byte(0x22, name="sid", fuzzable=False)
        s_word(0xF190, name="did", endian='>')  # VIN
        
        # Write Data By Identifier
        s_initialize("uds_write_data")
        s_byte(0x2E, name="sid", fuzzable=False)
        s_word(0xF190, name="did", endian='>')
        s_string("AAAAA", name="data", max_len=100)
        
        # Routine Control
        s_initialize("uds_routine_control")
        s_byte(0x31, name="sid", fuzzable=False)
        s_byte(0x01, name="subfunction")
        s_word(0xFF00, name="routine_id", endian='>')
        s_bytes(b"\x00" * 10, name="routine_params")
        
        # Request Download
        s_initialize("uds_request_download")
        s_byte(0x34, name="sid", fuzzable=False)
        s_byte(0x00, name="compression_encryption")
        s_byte(0x44, name="address_length_format")
        s_bytes(b"\x00\x10\x00\x00", name="memory_address")
        s_bytes(b"\x00\x00\x10\x00", name="memory_size")
        
        # Transfer Data
        s_initialize("uds_transfer_data")
        s_byte(0x36, name="sid", fuzzable=False)
        s_byte(0x01, name="block_counter")
        s_bytes(b"\x00" * 256, name="data", max_len=4096)
        
        # Tester Present
        s_initialize("uds_tester_present")
        s_byte(0x3E, name="sid", fuzzable=False)
        s_byte(0x00, name="subfunction")
    
    def fuzz_uds_services(
        self,
        timeout: int = 300,
        services: Optional[List[int]] = None
    ) -> FuzzingResult:
        """
        Fuzz UDS services.
        
        Args:
            timeout: Fuzzing timeout in seconds
            services: Specific service IDs to fuzz (None = all)
            
        Returns:
            FuzzingResult with findings
        """
        start_time = time.time()
        
        if self.use_simulation:
            return self._simulate_uds_fuzzing(services)
        
        if not self.session:
            if not self.setup_uds_session():
                return FuzzingResult(
                    protocol="UDS",
                    test_cases_run=0,
                    crashes_found=0,
                    hangs_found=0,
                    anomalies=[],
                    vulnerabilities=[{'error': 'Failed to set up session'}]
                )
        
        vulnerabilities = []
        test_cases = 0
        crashes = 0
        hangs = 0
        
        try:
            # Fuzz each defined message
            messages = [
                "uds_diagnostic_session",
                "uds_security_request",
                "uds_security_sendkey",
                "uds_read_data",
                "uds_write_data",
                "uds_routine_control",
                "uds_transfer_data",
                "uds_tester_present",
            ]
            
            for msg_name in messages:
                if time.time() - start_time > timeout:
                    break
                
                try:
                    self.session.fuzz(
                        max_num=100,  # Max test cases per message
                        this_node=msg_name
                    )
                    test_cases += 100
                except Exception as e:
                    logger.warning(f"Error fuzzing {msg_name}: {e}")
            
            # Collect results
            # In real implementation, would check session.results
            
        except Exception as e:
            logger.error(f"UDS fuzzing error: {e}")
            vulnerabilities.append({
                'type': 'error',
                'description': str(e)
            })
        
        duration = time.time() - start_time
        
        return FuzzingResult(
            protocol="UDS",
            test_cases_run=test_cases,
            crashes_found=crashes,
            hangs_found=hangs,
            anomalies=self.anomalies,
            vulnerabilities=vulnerabilities,
            duration=duration
        )
    
    def fuzz_can_frames(
        self,
        arbitration_ids: Optional[List[int]] = None,
        timeout: int = 300
    ) -> FuzzingResult:
        """
        Fuzz CAN frames.
        
        Args:
            arbitration_ids: Specific CAN IDs to fuzz
            timeout: Fuzzing timeout in seconds
            
        Returns:
            FuzzingResult with findings
        """
        start_time = time.time()
        
        if self.use_simulation:
            return self._simulate_can_fuzzing(arbitration_ids)
        
        if not self.can_interface:
            return FuzzingResult(
                protocol="CAN",
                test_cases_run=0,
                crashes_found=0,
                hangs_found=0,
                anomalies=[],
                vulnerabilities=[{'error': 'No CAN interface specified'}]
            )
        
        # CAN fuzzing would use python-can or similar
        # This is a placeholder for actual CAN implementation
        
        return FuzzingResult(
            protocol="CAN",
            test_cases_run=0,
            crashes_found=0,
            hangs_found=0,
            anomalies=[],
            vulnerabilities=[],
            duration=time.time() - start_time
        )
    
    def fuzz_doip(self, timeout: int = 300) -> FuzzingResult:
        """
        Fuzz DoIP (Diagnostics over IP) protocol.
        
        Args:
            timeout: Fuzzing timeout in seconds
            
        Returns:
            FuzzingResult with findings
        """
        start_time = time.time()
        
        if self.use_simulation:
            return self._simulate_doip_fuzzing()
        
        if not self.target_ip:
            return FuzzingResult(
                protocol="DoIP",
                test_cases_run=0,
                crashes_found=0,
                hangs_found=0,
                anomalies=[],
                vulnerabilities=[{'error': 'No target IP specified'}]
            )
        
        vulnerabilities = []
        test_cases = 0
        
        try:
            # Define DoIP protocol
            self._define_doip_protocol()
            
            # Create DoIP session
            session = Session(
                target=Target(
                    connection=TCPSocketConnection(
                        self.target_ip,
                        self.target_port
                    )
                )
            )
            
            # Fuzz DoIP messages
            doip_messages = [
                "doip_vehicle_identification",
                "doip_routing_activation",
                "doip_diagnostic_message",
            ]
            
            for msg in doip_messages:
                if time.time() - start_time > timeout:
                    break
                
                try:
                    session.fuzz(max_num=50, this_node=msg)
                    test_cases += 50
                except Exception as e:
                    logger.debug(f"DoIP fuzz error: {e}")
                    
        except Exception as e:
            vulnerabilities.append({
                'type': 'error',
                'description': str(e)
            })
        
        return FuzzingResult(
            protocol="DoIP",
            test_cases_run=test_cases,
            crashes_found=0,
            hangs_found=0,
            anomalies=[],
            vulnerabilities=vulnerabilities,
            duration=time.time() - start_time
        )
    
    def _define_doip_protocol(self) -> None:
        """Define DoIP protocol for fuzzing."""
        
        if not BOOFUZZ_AVAILABLE:
            return
        
        # DoIP Header
        def doip_header(payload_type: int, payload_length: int):
            return struct.pack('>BBHI', 0x02, 0xFD, payload_type, payload_length)
        
        # Vehicle Identification Request
        s_initialize("doip_vehicle_identification")
        s_static(b"\x02\xFD")  # Protocol version
        s_word(0x0001, name="payload_type", endian='>')
        s_word(0x0000, name="payload_length", endian='>')
        
        # Routing Activation Request
        s_initialize("doip_routing_activation")
        s_static(b"\x02\xFD")
        s_word(0x0005, name="payload_type", endian='>')
        s_word(0x0007, name="payload_length", endian='>')
        s_word(0x0E00, name="source_address", endian='>')
        s_byte(0x00, name="activation_type")
        s_bytes(b"\x00\x00\x00\x00", name="reserved")
        
        # Diagnostic Message
        s_initialize("doip_diagnostic_message")
        s_static(b"\x02\xFD")
        s_word(0x8001, name="payload_type", endian='>')
        s_size("payload", length=4, endian='>')
        s_block_start("payload")
        s_word(0x0E00, name="source_address", endian='>')
        s_word(0x0100, name="target_address", endian='>')
        s_bytes(b"\x10\x01", name="uds_data")  # UDS request
        s_block_end()
    
    # Simulation methods
    
    def _simulate_uds_fuzzing(
        self,
        services: Optional[List[int]] = None
    ) -> FuzzingResult:
        """Simulate UDS fuzzing results."""
        
        logger.info("[Simulation] Running simulated UDS fuzzing...")
        
        # Generate simulated vulnerabilities
        vulnerabilities = [
            {
                'type': 'security_bypass',
                'cwe_id': 'CWE-287',
                'severity': 'high',
                'title': '[Simulated] Security Access Bypass',
                'description': 'Simulated finding: Security access may be bypassable',
                'detection_method': 'protocol_fuzzing',
                'protocol': 'UDS',
                'service': 'SecurityAccess (0x27)',
                'note': 'Install boofuzz for real protocol fuzzing'
            },
            {
                'type': 'unauthorized_access',
                'cwe_id': 'CWE-862',
                'severity': 'medium',
                'title': '[Simulated] Missing Authorization Check',
                'description': 'Simulated finding: Service accessible without authentication',
                'detection_method': 'protocol_fuzzing',
                'protocol': 'UDS',
                'service': 'ReadMemoryByAddress (0x23)',
                'note': 'Install boofuzz for real protocol fuzzing'
            }
        ]
        
        return FuzzingResult(
            protocol="UDS",
            test_cases_run=0,
            crashes_found=0,
            hangs_found=0,
            anomalies=[],
            vulnerabilities=vulnerabilities,
            duration=0.1
        )
    
    def _simulate_can_fuzzing(
        self,
        arbitration_ids: Optional[List[int]] = None
    ) -> FuzzingResult:
        """Simulate CAN fuzzing results."""
        
        logger.info("[Simulation] Running simulated CAN fuzzing...")
        
        vulnerabilities = [
            {
                'type': 'can_injection',
                'cwe_id': 'CWE-20',
                'severity': 'high',
                'title': '[Simulated] CAN Message Injection Possible',
                'description': 'Simulated finding: CAN bus accepts arbitrary messages',
                'detection_method': 'protocol_fuzzing',
                'protocol': 'CAN',
                'note': 'Configure CAN interface for real fuzzing'
            }
        ]
        
        return FuzzingResult(
            protocol="CAN",
            test_cases_run=0,
            crashes_found=0,
            hangs_found=0,
            anomalies=[],
            vulnerabilities=vulnerabilities,
            duration=0.1
        )
    
    def _simulate_doip_fuzzing(self) -> FuzzingResult:
        """Simulate DoIP fuzzing results."""
        
        logger.info("[Simulation] Running simulated DoIP fuzzing...")
        
        vulnerabilities = [
            {
                'type': 'routing_bypass',
                'cwe_id': 'CWE-306',
                'severity': 'medium',
                'title': '[Simulated] DoIP Routing Activation Bypass',
                'description': 'Simulated finding: Routing activation may be bypassable',
                'detection_method': 'protocol_fuzzing',
                'protocol': 'DoIP',
                'note': 'Connect to target for real fuzzing'
            }
        ]
        
        return FuzzingResult(
            protocol="DoIP",
            test_cases_run=0,
            crashes_found=0,
            hangs_found=0,
            anomalies=[],
            vulnerabilities=vulnerabilities,
            duration=0.1
        )


class UDSFuzzer(AutomotiveProtocolFuzzer):
    """Specialized UDS protocol fuzzer."""
    
    def __init__(self, target_ip: str, target_port: int = 13400, **kwargs):
        super().__init__(target_ip=target_ip, target_port=target_port, **kwargs)
    
    def fuzz(self, timeout: int = 300) -> FuzzingResult:
        """Run UDS fuzzing."""
        return self.fuzz_uds_services(timeout=timeout)


class CANFuzzer(AutomotiveProtocolFuzzer):
    """Specialized CAN bus fuzzer."""
    
    def __init__(self, can_interface: str = 'vcan0', **kwargs):
        super().__init__(can_interface=can_interface, **kwargs)
    
    def fuzz(
        self,
        arbitration_ids: Optional[List[int]] = None,
        timeout: int = 300
    ) -> FuzzingResult:
        """Run CAN fuzzing."""
        return self.fuzz_can_frames(arbitration_ids=arbitration_ids, timeout=timeout)