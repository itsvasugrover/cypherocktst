#include "crypto.hpp"
#include "logger.hpp"
#include <iostream>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <sstream>

extern "C" {
#include "sha2.h"
#include "ecdsa.h"
#include "secp256k1.h"
#include "rand.h"
}

// Predefined H Point
const std::vector<uint8_t> H_POINT_BYTES = {
    0x04, 0xc6, 0x04, 0x7f, 0x94, 0x41, 0xed, 0x7d, 0x6d, 0x30, 0x45, 0x40, 0x6e, 0x95, 0xc0, 0x7c, 0xd8, 
    0x5c, 0x77, 0x8e, 0x4b, 0x8c, 0xef, 0x3c, 0xa7, 0xab, 0xac, 0x09, 0xb9, 0x5c, 0x70, 0x9e, 0xe5,
    0x1a, 0xe1, 0x68, 0xfe, 0xa6, 0x3d, 0xc3, 0x39, 0xa3, 0xc5, 0x84, 0x19, 0x46, 0x6c, 0xea, 0xee, 
    0xf7, 0xf6, 0x32, 0x65, 0x32, 0x66, 0xd0, 0xe1, 0x23, 0x64, 0x31, 0xa9, 0x50, 0xcf, 0xe5, 0x2a
};

static std::string hex_str(const std::vector<uint8_t>& data) {
    std::stringstream ss;
    for (auto b : data) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

void CryptoUtils::print_hex(const std::vector<uint8_t>& data) {
    spdlog::trace("HEX: {}", hex_str(data));
}

std::vector<uint8_t> CryptoUtils::sha256(const std::string& input) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    sha256_Raw(reinterpret_cast<const uint8_t*>(input.data()), input.size(), digest.data());
    return digest;
}

std::vector<uint8_t> CryptoUtils::sha256(const std::vector<uint8_t>& input) {
    std::vector<uint8_t> digest(SHA256_DIGEST_LENGTH);
    sha256_Raw(input.data(), input.size(), digest.data());
    return digest;
}

std::vector<uint8_t> CryptoUtils::generate_random_bytes(size_t length) {
    std::vector<uint8_t> buf(length);
    random_buffer(buf.data(), length);
    return buf;
}

std::vector<uint8_t> CryptoUtils::sign_data(const std::vector<uint8_t>& private_key, const std::vector<uint8_t>& digest) {
    if (digest.size() != 32 || private_key.empty()) return {};
    std::vector<uint8_t> signature(64); 
    if (ecdsa_sign_digest(&secp256k1, private_key.data(), digest.data(), signature.data(), nullptr, nullptr) != 0) return {};
    return signature;
}

bool CryptoUtils::verify_signature(const std::vector<uint8_t>& public_key, const std::vector<uint8_t>& digest, const std::vector<uint8_t>& signature) {
    if (public_key.empty() || digest.size() != 32 || signature.size() != 64) return false;
    // ecdsa_verify returns 0 on SUCCESS
    return ecdsa_verify_digest(&secp256k1, public_key.data(), signature.data(), digest.data()) == 0;
}

// --- PEM Parsers ---
static const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static bool is_base64(uint8_t c) { return (isalnum(c) || (c == '+') || (c == '/')); }
std::vector<uint8_t> base64_decode(const std::string& encoded_string) {
    std::vector<uint8_t> decoded;
    int in_len = encoded_string.size();
    int i = 0; int j = 0; int in_ = 0;
    uint8_t char_array_4[4], char_array_3[3];
    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++) char_array_4[i] = base64_chars.find(char_array_4[i]);
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            for (i = 0; (i < 3); i++) decoded.push_back(char_array_3[i]);
            i = 0;
        }
    }
    if (i) {
        for (j = i; j < 4; j++) char_array_4[j] = 0;
        for (j = 0; j < 4; j++) char_array_4[j] = base64_chars.find(char_array_4[j]);
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        for (j = 0; (j < i - 1); j++) decoded.push_back(char_array_3[j]);
    }
    return decoded;
}

std::vector<uint8_t> CryptoUtils::load_private_key_from_pem(const std::string& pem) {
    size_t start = pem.find("-----BEGIN EC PRIVATE KEY-----");
    if (start == std::string::npos) return {};
    size_t end = pem.find("-----END EC PRIVATE KEY-----");
    if (end == std::string::npos) return {};
    start = pem.find('\n', start) + 1;
    std::string base64 = pem.substr(start, end - start);
    base64.erase(std::remove(base64.begin(), base64.end(), '\n'), base64.end());
    std::vector<uint8_t> der = base64_decode(base64);
    for(size_t i = 0; i < der.size() - 34; i++) {
        if (der[i] == 0x04 && der[i+1] == 0x20) return std::vector<uint8_t>(der.begin() + i + 2, der.begin() + i + 2 + 32);
    }
    return {};
}

std::vector<uint8_t> CryptoUtils::load_public_key_from_pem(const std::string& pem) {
    size_t start = pem.find("-----BEGIN PUBLIC KEY-----");
    if (start == std::string::npos) return {};
    size_t end = pem.find("-----END PUBLIC KEY-----");
    if (end == std::string::npos) return {};
    start = pem.find('\n', start) + 1;
    std::string base64 = pem.substr(start, end - start);
    base64.erase(std::remove(base64.begin(), base64.end(), '\n'), base64.end());
    std::vector<uint8_t> der = base64_decode(base64);
    if (der.size() >= 65) {
        size_t offset = der.size() - 65;
        if (der[offset] == 0x04) {
            std::vector<uint8_t> key(65);
            memcpy(key.data(), &der[offset], 65);
            return key;
        }
    }
    return {};
}

// --- RANGE PROOF MATH ---

static void uint32_to_bn(uint32_t val, bignum256* bn) {
    bn_zero(bn);
    bn->val[0] = val; 
}

static bool read_point_safe(const std::vector<uint8_t>& buf, curve_point* p, const char* name) {
    if (buf.empty()) { spdlog::error("Range: {} empty", name); return false; }
    
    // IMPORTANT: Trezor ecdsa_read_pubkey returns 1 on SUCCESS and 0 on FAILURE. Stupid design.
    int res = ecdsa_read_pubkey(&secp256k1, buf.data(), p);
    
    if (res == 0) {
        spdlog::error("Range: Failed to read {} (Size: {}). Error: {}", name, buf.size(), res);
        return false;
    }
    return true;
}

bool CryptoUtils::verify_range_proof_math(
    uint32_t min, uint32_t max, 
    const std::vector<uint8_t>& c1_bytes, 
    const std::vector<uint8_t>& c2_bytes,
    const std::vector<std::vector<uint8_t>>& squares
) {
    spdlog::info("DEBUG: Verifying Proof for [{}, {}]", min, max);

    curve_point C1, C2, H, G;
    bignum256 bn_min, bn_max;
    
    // Load Points
    if (!read_point_safe(c1_bytes, &C1, "C1")) return false;
    if (!read_point_safe(c2_bytes, &C2, "C2")) return false;
    if (!read_point_safe(H_POINT_BYTES, &H, "H")) return false;
    
    memcpy(&G, &secp256k1.G, sizeof(curve_point));

    // Load Scalars
    uint32_to_bn(min, &bn_min);
    uint32_to_bn(max, &bn_max);

    // P1 = (b * G) - C1
    curve_point P1, TermA;
    point_multiply(&secp256k1, &bn_max, &G, &TermA); 
    
    curve_point C1_Neg = C1;
    bn_subtract(&secp256k1.prime, &C1_Neg.y, &C1_Neg.y); 
    
    P1 = TermA;
    point_add(&secp256k1, &C1_Neg, &P1); 

    // P2 = C2 + (a * G)
    curve_point P2, TermB;
    point_multiply(&secp256k1, &bn_min, &G, &TermB);
    
    P2 = C2;
    point_add(&secp256k1, &TermB, &P2);

    // Squares
    if (squares.size() != 4) return false;
    curve_point SumSquares;
    curve_point SqTemp;
    
    if (!read_point_safe(squares[0], &SumSquares, "Sq0")) return false;

    for(int i=1; i<4; i++) {
        if (!read_point_safe(squares[i], &SqTemp, "SqX")) return false;
        point_add(&secp256k1, &SqTemp, &SumSquares);
    }

    // Check
    bool linear_ok = bn_is_equal(&P1.x, &P2.x) && bn_is_equal(&P1.y, &P2.y);
    bool square_ok = bn_is_equal(&SumSquares.x, &P2.x) && bn_is_equal(&SumSquares.y, &P2.y);

    if (!linear_ok) spdlog::warn("Range: Linear Check Failed");
    if (!square_ok) spdlog::warn("Range: Square Check Failed");

    return linear_ok && square_ok;
}