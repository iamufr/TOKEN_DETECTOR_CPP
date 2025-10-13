# TOKEN DETECTOR
A **production-grade token and secret detection library** written in modern C++ with performance, security, and correctness as top priorities. It is designed to find common token formats like UUIDs, JWTs, API keys, and SHA hashes within text.

## ✨ Features

  * **Multi-Token Support** – Detects UUIDs, JWTs, prefixed API keys, JSON service account keys, and SHA hashes (224, 256, 384, 512).
  * **High-Performance Scanning** – Utilizes lookup tables, branch prediction hints, and efficient scanning algorithms for maximum speed.
  * **Thread-Safe** – Designed for safe concurrent usage in multi-threaded environments.
  * **Security Hardened** – Implements input size limits to prevent Denial of Service (DoS) attacks.
  * **SOLID Principles** – Code is structured using SOLID principles for maintainability and extensibility.
  * **Duplicate & Overlap-Free** – Extracts unique, non-overlapping tokens from text.
  * **Comprehensive Test Suite** – Includes validation tests, scanning tests, and a multi-threaded performance benchmark.

## 📌 Use Cases

  * Scan logs, user input, or code for accidentally leaked secrets.
  * Data loss prevention (DLP) systems.
  * Pre-process text for compliance checks (e.g., GDPR, CCPA).
  * Identify and categorize different types of identifiers in large text corpora.

## 🚀 Included Components

  * `TokenScanner` – The core detection and extraction logic.
  * `ITokenValidator` Interfaces – Individual validators for each token type (UUID, JWT, etc.).
  * `TokenDetectorTest` – A framework for correctness, scanning, and performance testing.
  * `TokenDetectorFactory` – A factory for creating scanner and validator instances.
  * Example usage and a full test suite in `main()`.

## 🔧 Build Instructions

### Optimized Build (Recommended for Production)

For maximum performance with aggressive optimizations:

#### GCC 
**For development:**
```bash
g++ -O3 -march=native -std=c++17 -pthread TokenDetector.cpp -o TokenDetector
```

#### GCC 
**For production/benchmarking:**
```bash
g++ -O3 -march=native -flto=auto -DNDEBUG -std=c++17 -pthread TokenDetector.cpp -o TokenDetector
```

#### Clang
```bash
clang++ -O3 -march=native -std=c++17 -pthread TokenDetector.cpp -o TokenDetector
```

#### With Link-Time Optimization (even faster)
```bash
g++ -O3 -march=native -flto -std=c++17 -pthread TokenDetector.cpp -o TokenDetector
```

**Compiler Flags Explained:**
- `-O3` – Maximum optimization level (~20x speedup)
- `-march=native` – CPU-specific optimizations (SIMD, AVX)
- `-std=c++17` – C++17 standard support
- `-pthread` – POSIX threading support
- `-flto` – Link-time optimization (optional, slower compile)

**Performance:** ~600K operations/second on modern hardware

-----

### Unoptimized Build (Debug Mode)

For development, debugging, and getting more detailed error messages:

```bash
g++ -g -std=c++17 -pthread TokenDetector.cpp -o TokenDetector
```

  * `-g` – Includes debugging information in the binary for use with tools like GDB.

-----

## ▶️ Running the Program

### Linux/macOS
```bash
./TokenDetector
```

### Windows (PowerShell)
```powershell
./TokenDetector.exe
```

### Windows (CMD)
```cmd
TokenDetector.exe
```

---

## 📊 Expected Output

Running the program will first execute the validation and scanning test suites, followed by a live demo and a high-throughput performance benchmark. The output will look similar to this:

```
====================================================================================================
=== TOKEN VALIDATION TESTS ===
====================================================================================================
Γ£ô Standard UUID v4
Γ£ô Another valid UUID
Γ£ô Invalid UUID (too short)
Γ£ô Invalid UUID (extra char)
Γ£ô Valid JWT
Γ£ô Short JWT
Γ£ô Invalid JWT (segments too short)
Γ£ô Stripe-style secret key
Γ£ô Stripe-style public key
Γ£ô Too short (need 10+ chars after prefix)
Γ£ô Too short overall
Γ£ô Valid SHA-224
Γ£ô Valid SHA-256
Γ£ô Valid SHA-384
Γ£ô Valid SHA-512
Result: 15/15 passed (100%)
====================================================================================================
=== TOKEN SCANNING TESTS ===
====================================================================================================
Γ£ô UUID in text
  Found 1 token(s)
    [UUID] 550e8400-e29b-41d4-a716-446655440000
Γ£ô JWT in text
  Found 1 token(s)
    [JWT] eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3...
Γ£ô Simple API key
  Found 1 token(s)
    [API_KEY_SIMPLE] sk_live_12345abcde67890fghij11223
Γ£ô SHA-256 in text
  Found 1 token(s)
    [SHA-256] e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7...
Γ£ô UUID and SHA-256
  Found 2 token(s)
    [UUID] 550e8400-e29b-41d4-a716-446655440000
    [SHA-256] e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7...
Γ£ô No tokens
  Found 0 token(s)
Γ£ô UUID, JWT and API_KEY type tokens
  Found 3 token(s)
    [UUID] c9a6b4c8-4a6e-4b0f-8f1d-2e3c7d6a5b4e
    [JWT] eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvcGhvcy1rZ...
    [API_KEY_JSON] {"type":"service_account","project_id":"global-data-pipel...
Γ£ô JSON API key
  Found 1 token(s)
    [API_KEY_JSON] {"type":"service_account","project_id":"test-project","pr...
Result: 8/8 passed (100%)
====================================================================================================
=== TOKEN DETECTION DEMO ===
====================================================================================================
This is the paragraph that contains tokens.
Found Tokens:
1. [UUID: c9a6b4c8-4a6e-4b0f-8f1d-2e3c7d6a5b4e]
2. [JWT: eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNvcGhvcy1rZXktMjAyNCJ9.eyJhdWQi...]
3. [API_KEY_JSON: {"type":"service_account","project_id":"global-data-pipeline","private_key_id...]
====================================================================================================
====================================================================================================
=== PERFORMANCE BENCHMARK ===
====================================================================================================
Threads: 16
Iterations per thread: 100000
Test cases: 12
Total operations: 19200000
Starting benchmark...
----------------------------------------------------------------------------------------------------
RESULTS:
----------------------------------------------------------------------------------------------------
Time: 28112 ms
Ops/sec: 682982
Text scans with tokens: 17600000
Total tokens found: 24000000
====================================================================================================
====================================================================================================
Γ£ô SOLID Principles Applied
Γ£ô Character Classification Lookup Tables
Γ£ô Thread-Safe Implementation
Γ£ô Production-Ready Performance
====================================================================================================
```

-----

## 🧪 Testing

The program includes a robust, self-contained test suite that runs automatically:

  * **Validation Tests:** Verifies that each `ITokenValidator` correctly identifies valid and invalid token formats.
  * **Scanning Tests:** Ensures the `TokenScanner` can accurately find and extract tokens from various text blocks.
  * **Performance Benchmark:** A multi-threaded stress test that measures the number of scan operations per second on your hardware.

-----

## 📋 Requirements

  * **Compiler:** A C++17 compatible compiler (e.g., GCC 7+, Clang 6+, MSVC v19.14+).
  * **OS:** Linux, macOS, or Windows.
  * **Hardware:** Any modern CPU. The optimized build will take advantage of CPU-specific instructions if `-march=native` is used.

-----

## ⚠️ Important Notes

### Portability and `-march=native`

The `-march=native` flag produces a binary that is highly optimized for the machine you compile it on. This binary may fail to run on a machine with an older or different CPU architecture. If you need a portable binary that can run on multiple systems, compile without this flag:

```bash
g++ -O3 -std=c++17 -pthread TokenDetector.cpp -o TokenDetector
```

### Windows and `-pthread`

On some Windows environments (like MinGW), the `-pthread` flag may not be necessary or available. If you encounter errors related to it, you can safely omit it for single-threaded builds or use the native Windows threading libraries if needed.

```bash
g++ -O3 -march=native -std=c++17 TokenDetector.cpp -o TokenDetector.exe
```

-----
