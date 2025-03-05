# Basic-Blockchain

## Project Overview
This is a basic implementation of a blockchain system written in C, demonstrating core blockchain concepts and leveraging system-level programming techniques.

## Features
- Implemented in C (C99 standard)
- Uses OpenSSL for cryptographic operations
- Supports multiple sanitizer options for debugging
- Cross-platform support (x86_64 and aarch64 architectures)

## Prerequisites
- CMake (version 3.10 or higher)
- OpenSSL development libraries
- GCC or Clang compiler with C99 support

## Build Options

### Compilation Flags
- Compilation includes `-Wall` and `-Wextra` for comprehensive warning coverage
- Optimization level set to `-O2`

### Sanitizer Options
The project supports several sanitizer options for debugging:

1. Address Sanitizer (ASAN):
   ```
   cmake -DENABLE_ASAN=ON ..
   ```
   Detects memory-related errors like buffer overflows.

2. Thread Sanitizer (TSAN):
   ```
   cmake -DENABLE_TSAN=ON ..
   ```
   Helps identify data races and threading issues.

3. Undefined Behavior Sanitizer (UBSAN):
   ```
   cmake -DENABLE_UBSAN=ON ..
   ```
   Catches undefined behavior in the code.

## Building the Project

```bash
mkdir build
cd build
cmake ..
make
```

## Running the Blockchain

```bash
./blockchain
```

## Dependencies
- OpenSSL (Crypto library)
- Check Unit Testing Framework (architecture-specific library)

## Supported Architectures
- x86_64
- aarch64

## Build Configurations
- Debug mode (default)
- Release mode available
