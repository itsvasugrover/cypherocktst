# Cypherock Technical Screening Task - SE Dec 2025

## Overview

The task involves building a secure system with a client-server architecture that implements range proof cryptographic operations. A range proof allows a prover (client) to demonstrate to a verifier (server) that a secret value lies within a specific range without revealing the actual value. The system uses Boost Asio for network operations, Trezor Crypto for cryptography, and nanopb for protocol buffers.

## Details

### 1. Setup

- Set up a TCP/IP based client and a server using Boost Asio.
- Set up Trezor Crypto at both client and server side.
- Set up nanopb (protocol buffer) at both client and server side.

### 2. Authentication Mechanism

Client is pre-provisioned with a 32 byte ECDSA private key and a serial ID. The public key corresponding to the client's private key is stored at the server. Perform all data encoding and decoding at client and server side using nanopb.

Also, client has the public key of the server.

- Client generates a signature on the hash of the serial ID and sends it to the server to start the auth session.
- At the server side, verify the signature using the client's public key and the hash of the serial ID.
- Once verified, the server generates a 32 byte random number and sends it to the client to generate a signature. This message is also signed by the server using its private key.
- Client verifies the server's signature using the server's public key and generates a signature on the random number and sends it to the server.
- Server verifies the client's signature using the client's public key and the random number.
- Server verifies the signature using hash of the random number and client's public key. If a signature gets verified, the server prints the client verified message along with its serial ID.

### 3. Service Mechanism

- Once the authentication is done, the client and server should implement the range proof protocol.
- Client generates a secret value $ v $ that it wants to prove lies within a range $[0, 2^n - 1]$ where $ n $ is a configurable parameter (e.g., $ n=32 $ for 32-bit range).
- Client generates a range proof for the value $ v $ using the range proof algorithm. The proof should demonstrate that $ v $ is within the specified range without revealing $ v $.
- Client sends the range proof along with the range parameters (minimum value, maximum value, and bit length $ n $) to the server.
- Server receives the range proof and verifies that the secret value lies within the specified range.
- Server returns a verification result (success/failure) to the client.
- Both client and server should print the verification status and relevant parameters (range bounds, bit length, but not the secret value).

### 4. Range Proof Algorithm

The range proof implementation follows the following mathematical structure:

#### Representation of Positive Values

Every positive value $ x $ can be represented as the sum of four squares:
$$
x = x_0^2 + x_1^2 + x_2^2 + x_3^2
$$

#### Commitment Creation (Modular Arithmetic)

The prover and verifier agree on two bases $ g $ and $ h $, and a prime number $ n $. The verifier sends the prover a random number $ r $ as a challenge.
The prover creates four commitments from the four values $ (x_0, x_1, x_2, x_3) $ using four random numbers $ (r_0, r_1, r_2, r_3) $:
$$
c_0 = g^{x_0^2} \cdot h^{r_0} \pmod{n}, \quad c_1 = g^{x_1^2} \cdot h^{r_1} \pmod{n}, \quad c_2 = g^{x_2^2} \cdot h^{r_2} \pmod{n}, \quad c_3 = g^{x_3^2} \cdot h^{r_3} \pmod{n}
$$
where $ r = r_0 + r_1 + r_2 + r_3 $.

#### Verifier's Check

The verifier checks the combined commitment:
$$
C = c_0 \cdot c_1 \cdot c_2 \cdot c_3
$$
This should equal:
$$
C = g^x \cdot h^r \pmod{n}
$$

#### Range Proof

To prove that a value $ x $ lies within the range $[a, b]$, the prover demonstrates that both $ (x - a) $ and $ (b - x) $ are positive.
Two commitments are computed:
$$
c_1 = g^{(b-x)} \cdot h^{-r} \pmod{n}, \quad c_2 = g^{(x-a)} \cdot h^r \pmod{n}
$$
To verify these commitments, the verifier computes:
$$
p_1 = g^b / c_1 \pmod{n}, \quad p_2 = c_2 \cdot g^a \pmod{n}
$$
Both $ p_1 $ and $ p_2 $ should equal $ g^x \cdot h^r \pmod{n} $.

#### Elliptic Curve Cryptography (ECC) Implementation

The algorithm is implemented using elliptic curve cryptography. Starting with two points on the curve $ G $ and $ H $, the commitments are computed as:
$$
C_0 = (x_0^2) \cdot G + (r_0) \cdot H, \quad C_1 = (x_1^2) \cdot G + (r_1) \cdot H, \quad C_2 = (x_2^2) \cdot G + (r_2) \cdot H, \quad C_3 = (x_3^2) \cdot G + (r_3) \cdot H
$$
The verifier checks:
$$
C = C_0 + C_1 + C_2 + C_3
$$
and verifies that this equals:
$$
x \cdot G + r \cdot H
$$
For the range proof in ECC:
$$
c_1 = (b - x) \cdot G - r \cdot H, \quad c_2 = (x - a) \cdot G + r \cdot H
$$
The verifier computes:
$$
p_1 = b \cdot G - c_1, \quad p_2 = c_2 + a \cdot G
$$
The verifier then checks that $ p_1 $ equals $ p_2 $.

### 5. Requirements

#### 1. For server

- Use C++ for implementation.
- Use Trezor Crypto for all crypto operations.
- Use Boost Asio for all the network operations.
- Use nanopb for all the protocol buffer operations.

#### 2. For client

- Use Node.js for implementation.
- Use TypeScript as the language for implementation.
- Use crypto module for all the crypto operations.
- Use net module for all the network operations.
- Use protobufjs for all the protocol buffer operations.

#### 3. Generic Requirements

- Use ECDSA for all the signatures.
- Use the secp256k1 curve for all the signing crypto operations.
- Use the SHA256 hash function for all the hashes.
- Use of OOP and relevant design patterns and data structures along with good coding practices.
- The range proof implementation must follow the algorithm specified in the Range Proof Algorithm section.

#### 4. Good To Have

- Use CMake for the build system (for the C++ part).
- Implementation is protected from well-known attacks.
- Support for multiple range proof requests in a single session.
- Configurable range parameters (minimum, maximum, bit length) via command line or configuration file.

### Submission

- Provide the source code as a zipped folder.
- Do not make the solution public, else you will be disqualified.
- Provide a README file with the details of the implementation and the build instructions.

**Note:** The submission should be submitted via email to [hiring@cypherock.com](hiring@cypherock.com). Please include your resume along with your submission. Deadline - 2 Days.

### References

#### Boost Asio

- [Boost Asio Example](https://www.codingwiththomas.com/blog/boost-asio-server-client-example)
- [Boost TCP Server Client](https://github.com/alejandrofsevilla/boost-tcp-server-client)

#### Trezor Crypto

- [Trezor Crypto](https://github.com/trezor/trezor-crypto)

#### Protocol Buffer

- [Protocol Buffer Overview](https://protobuf.dev/overview/)
- [Nanopb GitHub](https://github.com/nanopb/nanopb)
- [Protobuf.js npm](https://www.npmjs.com/package/protobufjs)
- [Nanopb Docs](https://jpa.kapsi.fi/nanopb/docs/)

#### ECDSA concepts

- [ECDSA Video 1](https://www.youtube.com/watch?v=iB3HcPgm_FI)
- [ECDSA Video 2](https://www.youtube.com/watch?v=U2bw_N6kQL8)
