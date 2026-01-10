#pragma once
#include <vector>
#include <string>
#include <cstdint>

class CryptoUtils {
public:
    // Debug helper
    static void print_hex(const std::vector<uint8_t>& data);

    // Hashing
    static std::vector<uint8_t> sha256(const std::string& input);
    static std::vector<uint8_t> sha256(const std::vector<uint8_t>& input);

    // ECDSA Sign/Verify
    static std::vector<uint8_t> sign_data(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& digest);
    static bool verify_signature(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& digest, const std::vector<uint8_t>& signature);

    // PEM Parsing
    static std::vector<uint8_t> load_private_key_from_pem(const std::string& pem);
    static std::vector<uint8_t> load_public_key_from_pem(const std::string& pem);

    // Random
    static std::vector<uint8_t> generate_random_bytes(size_t length);

    // Range Proof Math
    // Verifies: (b*G - C1) == (C2 + a*G) AND Sum(Squares) == (C2 + a*G)
    static bool verify_range_proof_math(
        uint32_t min, uint32_t max, 
        const std::vector<uint8_t>& c1, 
        const std::vector<uint8_t>& c2,
        const std::vector<std::vector<uint8_t>>& squares
    );
};