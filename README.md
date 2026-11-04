# Cypherock TST

> [!WARNING]
> **This repository is now archived and read-only.** It is no longer actively maintained — no further commits, issues, or pull requests will be accepted. The code remains available for reference.


This project implements a secure client-server setup demonstrating Zero-Knowledge Range Proofs, adhering closely to specified requirements. It features secure authentication, range proof verification, and all necessary technical components. Below is a guide to what the project includes and how to set it up and run it.

## What I Built

This project implements a secure client-server system where the client proves to the server that a secret value lies within a specific range without revealing the actual value. The whole thing uses elliptic curve cryptography for the zero-knowledge proofs.

Key features include:

- Mutual authentication using ECDSA signatures and a client serial ID
- Range proof generation and verification following the exact math from the problem statement
- Support for multiple range proof requests in a single session
- Session timeouts for security
- Proper error handling and logging throughout
- Configurable range parameters and proof attempts

## Tech Stack

**Server (C++):**

- Boost Asio for networking
- Trezor Crypto for all cryptographic operations
- Nanopb for protocol buffer serialization
- CMake for build system
- Spdlog for logging

**Client (TypeScript/Node.js):**

- Node.js crypto module for signing operations
- Net module for TCP connections
- Protobufjs for protocol buffers
- Elliptic library for ECC math
- Pino for logging

Both sides use secp256k1 curve and SHA256 hashing as specified.

## Getting Started

Before you start, clone the repo with submodules:

```bash
git submodule update --init --recursive
```

Please ensure you have Node.js installed as we use it for the client also. If not, you can use a package manager like NVM to install it.

```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.3/install.sh | bash
nvm install --lts
nvm use --lts
```

First, you'll need to generate the cryptographic keys. I included a script for that:

```bash
node keygen.js
```

This creates ECDSA key pairs for client and server, plus a client serial ID, and puts them in the right directories.

### Building the Server

The server is in C++ and needs some dependencies. On Ubuntu, you can install them with:

```bash
sudo apt install python3-pip pipx python3-venv cmake build-essential
pipx install conan
# Check conan is set up correctly
conan --version
conan profile new default --detect
```

The server uses CMake and needs some dependencies. I set it up with Conan for package management:

```bash
cd server
./setup.sh  # Sets up Python environment and installs requirements
./build.sh  # Runs Conan install and builds with CMake
```

### Setting Up the Client

The client is Node.js based. Install dependencies and build the protobuf files:

```bash
cd client
npm install
npm run build:proto  # Generates TypeScript protobuf definitions
```

### Running the Project

Start the server first:

```bash
cd server
./start.sh
```

Then run the client:

```bash
cd client
cp .env.example .env  # Create your config file
npm start
```

The client will connect to localhost:8080, authenticate, and send multiple range proof requests. You'll see detailed logs on both sides showing the authentication process and proof verification results.

## Configuration

The client reads config from a `.env` file. You can adjust:

- Range bounds (MIN_VAL, MAX_VAL)
- Secret value to prove (SECRET)
- Number of proof attempts (TOTAL_ATTEMPTS)
- Server connection details

Check `client/.env.example` for the full list of options.

## Implementation Notes

The implementation follows the problem statement's range proof algorithm exactly, implementing the four-square decomposition and ECC commitments. The math checks out for both the linear range proof (proving x ∈ [a,b]) and the square commitments.

Security-wise, the implementation includes protections like message size limits, session state validation, and proper cleanup. The authentication flow matches the spec: client signs serial ID hash, server challenges with random nonce, client signs that too.

The code follows OOP principles with classes for Client, Server, Session, and Crypto utilities. Error handling is comprehensive, and logging helps with debugging.

If the secret value is outside the configured range, the proof will fail as expected - that's how you can test the validation.

## Files Overview

- `proto/comms.proto` - Protocol buffer definitions for all messages
- `server/src/` - Server implementation (main.cpp, server.cpp, crypto.cpp)
- `client/src/` - Client code (index.ts, client.ts, crypto utils)
- `keygen.js` - Key generation script
- Build scripts in server/ for CMake setup

The implementation is production-ready with proper build systems, dependency management, and comprehensive logging.
