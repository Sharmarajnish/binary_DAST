/*
 * Sample Vulnerable ECU - Engine Control Module
 * For DAST Testing
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// CWE-798: Hardcoded Credentials
const char *SECRET_KEY = "JLR_ECU_2024_SECRET";
const uint32_t SEED_VALUE = 0xDEADBEEF;

// CWE-120: Buffer Overflow
void process_vin(char *vin_input) {
  char vin_buffer[17];           // VIN is 17 chars
  strcpy(vin_buffer, vin_input); // VULNERABLE: no bounds check
  printf("VIN: %s\n", vin_buffer);
}

// CWE-134: Format String
void log_message(char *msg) {
  printf(msg); // VULNERABLE: user-controlled format string
}

// CWE-190: Integer Overflow
void allocate_dtc_buffer(uint16_t count) {
  uint32_t size = count * sizeof(uint32_t); // VULNERABLE: can overflow
  uint32_t *buffer = malloc(size);
  if (buffer) {
    memset(buffer, 0, size);
    free(buffer);
  }
}

// CWE-416: Use After Free
static char *global_buffer = NULL;

void process_sensor_data(char *data) {
  if (global_buffer)
    free(global_buffer);
  global_buffer = strdup(data);
  free(global_buffer);                 // VULNERABLE: freed
  printf("Data: %s\n", global_buffer); // Use after free
}

// CWE-306: Missing Authentication
void erase_flash_memory() {
  // VULNERABLE: No authentication check before critical operation
  printf("Erasing flash memory...\n");
}

// CWE-327: Weak Crypto
uint32_t calculate_key(uint32_t seed) {
  return seed ^ 0xFFFFFFFF; // VULNERABLE: simple XOR
}

// UDS Handler - Multiple vulnerabilities
void handle_uds_request(uint8_t *data, size_t len) {
  uint8_t service = data[0];

  switch (service) {
  case 0x10: // Diagnostic Session
    printf("Session control\n");
    break;
  case 0x27: // Security Access
    if (data[1] == 0x01) {
      printf("Seed: 0x%08X\n", SEED_VALUE); // CWE-798
    } else {
      uint32_t key = *(uint32_t *)&data[2];
      if (key == calculate_key(SEED_VALUE)) {
        printf("Authenticated\n");
      }
    }
    break;
  case 0x2E:                       // Write Data
    process_vin((char *)&data[2]); // CWE-120
    break;
  case 0x31:              // Routine Control
    erase_flash_memory(); // CWE-306
    break;
  }
}

int main(int argc, char *argv[]) {
  printf("Engine ECU v1.0 - Test Binary\n");

  if (argc > 1) {
    log_message(argv[1]); // CWE-134
  }

  return 0;
}
