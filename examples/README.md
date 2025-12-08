# Example Test Files

This folder contains sample files for testing the DAST Scanner.

## Files

| File | Format | Description |
|------|--------|-------------|
| `engine_ecu.c` | ANSI C | Vulnerable C source with 7 CWEs |
| `sample_ecu.vbf` | VBF | Volvo Binary Format sample |
| `ecu_config.arxml` | AUTOSAR | ARXML configuration |
| `firmware.hex` | Intel HEX | Hex format firmware |
| `firmware.s19` | S-Record | Motorola S-Record format |
| `sample.bin` | Raw Binary | Generic binary file |
| `vulnerable_ecu.elf` | ELF | Compiled vulnerable ECU (if available) |

## Usage

1. Open http://localhost:3000
2. Click **New Scan**
3. Upload any file from this folder
4. Configure analysis modules
5. Start scan

## Expected Results

### engine_ecu.c (SAST)
Should detect:
- CWE-798: Hardcoded credentials
- CWE-120: Buffer overflow (strcpy)
- CWE-134: Format string
- CWE-190: Integer overflow
- CWE-416: Use after free
- CWE-306: Missing authentication
- CWE-327: Weak cryptography

### sample_ecu.vbf
Should parse:
- Software part number
- ECU address
- Checksum validation

### ecu_config.arxml
Should extract:
- ECU instances
- Software components
- CAN cluster configuration
