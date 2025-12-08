/*
 * Vulnerable ECU Simulator for DAST Testing
 * 
 * Compile (x86_64): 
 *   gcc -o vulnerable_ecu vulnerable_ecu.c -no-pie -fno-stack-protector
 * 
 * Cross-compile (ARM):
 *   arm-linux-gnueabi-gcc -o vulnerable_ecu_arm vulnerable_ecu.c -static -no-pie -fno-stack-protector
 * 
 * Contains intentional vulnerabilities for testing:
 * - CWE-120: Buffer Overflow
 * - CWE-134: Format String
 * - CWE-190: Integer Overflow
 * - CWE-416: Use-After-Free
 * - CWE-798: Hardcoded Credentials
 * - CWE-306: Missing Authentication
 * - CWE-327: Weak Cryptography
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Simulated CAN message structure
typedef struct {
    uint32_t can_id;
    uint8_t dlc;
    uint8_t data[8];
} can_message_t;

// Simulated UDS request
typedef struct {
    uint8_t service_id;
    uint8_t sub_function;
    uint8_t data[256];
    uint16_t data_len;
} uds_request_t;

// Global state
int authenticated = 0;
char *dynamic_buffer = NULL;

// Hardcoded seed/key (CWE-798: Hardcoded Credentials)
const uint32_t SECRET_SEED = 0x12345678;
const uint32_t SECRET_KEY = 0xDEADBEEF;

// VULNERABILITY 1: Buffer Overflow (CWE-120)
void process_can_message(can_message_t *msg) {
    char buffer[8];
    
    printf("[ECU] Processing CAN message ID: 0x%X\n", msg->can_id);
    
    // VULNERABLE: No bounds check!
    memcpy(buffer, msg->data, msg->dlc);  // dlc can be > 8
    
    printf("[ECU] Processed %d bytes\n", msg->dlc);
}

// VULNERABILITY 2: Format String (CWE-134)
void log_diagnostic_message(char *message) {
    printf("[ECU] Diagnostic: ");
    printf(message);  // VULNERABLE: user-controlled format string
    printf("\n");
}

// VULNERABILITY 3: Integer Overflow (CWE-190)
void allocate_memory_for_flash(uint32_t size, uint32_t count) {
    uint32_t total_size = size * count;  // VULNERABLE: can overflow
    
    if (total_size > 0) {
        char *buffer = malloc(total_size);
        if (buffer) {
            printf("[ECU] Allocated %u bytes for flash\n", total_size);
            free(buffer);
        }
    }
}

// VULNERABILITY 4: Use-After-Free (CWE-416)
void process_dynamic_data(char *data, size_t len) {
    if (dynamic_buffer) {
        free(dynamic_buffer);
    }
    
    dynamic_buffer = malloc(len);
    memcpy(dynamic_buffer, data, len);
    
    printf("[ECU] Processing: %s\n", dynamic_buffer);
    
    // VULNERABLE: Still accessible after free
    free(dynamic_buffer);
    
    // Later use (simulated by another function call)
    printf("[ECU] Reusing buffer: %s\n", dynamic_buffer);  // Use-after-free!
}

// VULNERABILITY 5: SQL Injection pattern (CWE-89)
void query_vehicle_data(char *vin) {
    char query[256];
    
    // VULNERABLE: Unsanitized input
    sprintf(query, "SELECT * FROM vehicle_data WHERE vin='%s'", vin);
    
    printf("[ECU] Executing query: %s\n", query);
}

// VULNERABILITY 6: Missing Authentication (CWE-306)
void unlock_diagnostic_services() {
    // VULNERABLE: No actual authentication check
    authenticated = 1;
    printf("[ECU] Diagnostic services unlocked\n");
}

// VULNERABILITY 7: Weak Seed-Key (CWE-327)
uint32_t generate_seed() {
    // VULNERABLE: Predictable seed
    return SECRET_SEED;
}

int verify_key(uint32_t key) {
    // VULNERABLE: Simple XOR
    return (key == (SECRET_SEED ^ 0xFFFFFFFF));
}

// UDS Service Handlers
void handle_diagnostic_session_control(uds_request_t *req) {
    printf("[ECU] UDS 0x10: Diagnostic Session Control\n");
    
    if (req->sub_function == 0x01) {
        printf("[ECU] Default session activated\n");
    } else if (req->sub_function == 0x03) {
        printf("[ECU] Extended diagnostic session activated\n");
        unlock_diagnostic_services();  // VULNERABLE: No auth needed
    }
}

void handle_security_access(uds_request_t *req) {
    printf("[ECU] UDS 0x27: Security Access\n");
    
    if (req->sub_function == 0x01) {
        // Request seed
        uint32_t seed = generate_seed();
        printf("[ECU] Seed: 0x%08X\n", seed);
    } else if (req->sub_function == 0x02) {
        // Send key
        uint32_t key = *(uint32_t*)req->data;
        
        if (verify_key(key)) {
            authenticated = 1;
            printf("[ECU] Authentication successful\n");
        } else {
            printf("[ECU] Authentication failed\n");
        }
    }
}

void handle_read_data_by_id(uds_request_t *req) {
    uint16_t did = (req->data[0] << 8) | req->data[1];
    
    printf("[ECU] UDS 0x22: Read Data By ID: 0x%04X\n", did);
    
    if (did == 0xF190) {
        // VIN
        printf("[ECU] VIN: SALGA2EV9HA000001\n");
    } else if (did == 0xF18C) {
        // ECU Serial Number
        printf("[ECU] Serial: 12345678\n");
    }
}

void handle_write_data_by_id(uds_request_t *req) {
    uint16_t did = (req->data[0] << 8) | req->data[1];
    
    printf("[ECU] UDS 0x2E: Write Data By ID: 0x%04X\n", did);
    
    if (!authenticated) {
        printf("[ECU] Error: Not authenticated\n");
        return;
    }
    
    // VULNERABLE: Buffer overflow in data copy
    char buffer[16];
    memcpy(buffer, req->data + 2, req->data_len - 2);
    
    printf("[ECU] Data written\n");
}

void handle_routine_control(uds_request_t *req) {
    printf("[ECU] UDS 0x31: Routine Control\n");
    
    uint16_t routine_id = (req->data[0] << 8) | req->data[1];
    
    if (routine_id == 0xFF00) {
        // Erase memory
        printf("[ECU] Erasing flash memory...\n");
    } else if (routine_id == 0xFF01) {
        // Check programming dependencies
        printf("[ECU] Checking dependencies...\n");
    }
}

// Main UDS dispatcher
void process_uds_request(uds_request_t *req) {
    switch (req->service_id) {
        case 0x10:
            handle_diagnostic_session_control(req);
            break;
        case 0x27:
            handle_security_access(req);
            break;
        case 0x22:
            handle_read_data_by_id(req);
            break;
        case 0x2E:
            handle_write_data_by_id(req);
            break;
        case 0x31:
            handle_routine_control(req);
            break;
        default:
            printf("[ECU] Unknown service: 0x%02X\n", req->service_id);
    }
}

// Main function - reads from stdin (for fuzzing)
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Vulnerable ECU Simulator v1.0\n");
        printf("Usage: %s <input_file>\n", argv[0]);
        printf("Or pipe data: echo <hex> | %s -\n", argv[0]);
        return 1;
    }
    
    FILE *input;
    
    if (strcmp(argv[1], "-") == 0) {
        input = stdin;
    } else {
        input = fopen(argv[1], "rb");
        if (!input) {
            perror("Error opening file");
            return 1;
        }
    }
    
    // Read input
    uint8_t buffer[1024];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), input);
    
    if (bytes_read < 1) {
        printf("[ECU] No data received\n");
        return 1;
    }
    
    printf("[ECU] Received %zu bytes\n", bytes_read);
    
    // Determine message type
    uint8_t msg_type = buffer[0];
    
    if (msg_type < 0x10) {
        // Treat as CAN message
        can_message_t can_msg;
        can_msg.can_id = 0x123;
        can_msg.dlc = buffer[0];
        memcpy(can_msg.data, buffer + 1, 8);
        
        process_can_message(&can_msg);
        
    } else {
        // Treat as UDS request
        uds_request_t uds_req;
        uds_req.service_id = buffer[0];
        uds_req.sub_function = buffer[1];
        uds_req.data_len = bytes_read - 2;
        memcpy(uds_req.data, buffer + 2, uds_req.data_len);
        
        process_uds_request(&uds_req);
    }
    
    if (input != stdin) {
        fclose(input);
    }
    
    return 0;
}
