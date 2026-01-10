#include "server.hpp"
#include <iostream>
#include <vector>
#include <string>
#include "pb_decode.h"
#include "keys.hpp"

static std::vector<uint8_t> g_last_nonce;

bool encode_bytes(pb_ostream_t *stream, const pb_field_t *field, void *const *arg) {
    const std::vector<uint8_t>* data = (const std::vector<uint8_t>*)*arg;
    if (!pb_encode_tag_for_field(stream, field)) return false;
    return pb_encode_string(stream, data->data(), data->size());
}

bool decode_string(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    size_t len = stream->bytes_left;
    std::string* dest = (std::string*)*arg;
    dest->resize(len);
    if (!pb_read(stream, (uint8_t*)dest->data(), len)) return false;
    return true;
}

bool decode_bytes(pb_istream_t *stream, const pb_field_t *field, void **arg) {
    size_t len = stream->bytes_left;
    std::vector<uint8_t>* dest = (std::vector<uint8_t>*)*arg;
    dest->resize(len);
    if (!pb_read(stream, dest->data(), len)) return false;
    return true;
}

void handle_client_message(const std::vector<uint8_t>& data, std::shared_ptr<Session> session) {
    spdlog::info("DEBUG: Starting manual decode loop. Data size: {}", data.size());
    spdlog::default_logger()->flush();

    pb_istream_t stream = pb_istream_from_buffer(data.data(), data.size());
    pb_wire_type_t wire_type;
    uint32_t tag;
    bool eof;

    while (pb_decode_tag(&stream, &wire_type, &tag, &eof)) {
        spdlog::info("DEBUG: Decoded tag: {}", tag);
        
        // CASE 1: Auth Init
        if (tag == comms_GenericMessage_auth_init_tag) {
            spdlog::info("DEBUG: Found AuthInit tag");
            std::string serial_id;
            std::vector<uint8_t> signature;

            comms_AuthInit msg = comms_AuthInit_init_default;
            msg.serial_id.funcs.decode = decode_string;
            msg.serial_id.arg = &serial_id;
            msg.signature.funcs.decode = decode_bytes;
            msg.signature.arg = &signature;

            pb_istream_t substream;
            if (!pb_make_string_substream(&stream, &substream)) {
                spdlog::error("AuthInit: Substream failed"); return;
            }
            if (!pb_decode(&substream, comms_AuthInit_fields, &msg)) {
                spdlog::error("AuthInit: Decode failed"); return;
            }
            pb_close_string_substream(&stream, &substream);

            spdlog::info("[Auth] Received AuthInit. Serial: {}", serial_id);
            if(serial_id.empty()) { spdlog::error("Empty Serial"); return; }

            // Verify
            auto client_pub = CryptoUtils::load_public_key_from_pem(CLIENT_PUB_KEY);
            if(client_pub.empty()) { spdlog::error("Key load failed"); return; }

            auto hash = CryptoUtils::sha256(serial_id);
            if(!CryptoUtils::verify_signature(client_pub, hash, signature)) {
                spdlog::error("AuthInit Signature Invalid"); return;
            }

            // Challenge
            auto nonce = CryptoUtils::generate_random_bytes(32);
            g_last_nonce = nonce;
            
            auto server_priv = CryptoUtils::load_private_key_from_pem(SERVER_PRIV_KEY);
            auto digest = CryptoUtils::sha256(nonce);
            auto sig = CryptoUtils::sign_data(server_priv, digest);

            comms_GenericMessage resp = comms_GenericMessage_init_zero;
            resp.which_payload = comms_GenericMessage_auth_challenge_tag;
            resp.payload.auth_challenge.random_number.funcs.encode = encode_bytes;
            resp.payload.auth_challenge.random_number.arg = &nonce;
            resp.payload.auth_challenge.server_signature.funcs.encode = encode_bytes;
            resp.payload.auth_challenge.server_signature.arg = &sig;
            
            session->send_message(resp);
            return; 
        }

        // CASE 2: Auth Response
        else if (tag == comms_GenericMessage_auth_response_tag) {
            spdlog::info("DEBUG: Found AuthResponse tag");
            std::vector<uint8_t> signature;
            comms_AuthResponse msg = comms_AuthResponse_init_default;
            msg.signature.funcs.decode = decode_bytes;
            msg.signature.arg = &signature;

            pb_istream_t substream;
            if (!pb_make_string_substream(&stream, &substream)) {
                spdlog::error("AuthResponse: Make substream failed"); return;
            }
            if (!pb_decode(&substream, comms_AuthResponse_fields, &msg)) {
                spdlog::error("AuthResponse: Decode failed: {}", PB_GET_ERROR(&substream)); return;
            }
            pb_close_string_substream(&stream, &substream);

            spdlog::info("DEBUG: AuthResponse decoded. Sig len: {}", signature.size());

            // LOGIC
            if(g_last_nonce.empty()) { spdlog::error("No session nonce"); return; }
            
            spdlog::info("DEBUG: Verifying Nonce Signature...");
            auto client_pub = CryptoUtils::load_public_key_from_pem(CLIENT_PUB_KEY);
            auto digest = CryptoUtils::sha256(g_last_nonce); // Hash expected nonce
            
            bool ok = CryptoUtils::verify_signature(client_pub, digest, signature);
            spdlog::info("[Auth] Client Verification Result: {}", ok ? "SUCCESS" : "FAILED");

            comms_GenericMessage resp = comms_GenericMessage_init_zero;
            resp.which_payload = comms_GenericMessage_auth_status_tag;
            resp.payload.auth_status.authenticated = ok;
            
            spdlog::info("DEBUG: Sending AuthStatus...");
            session->send_message(resp);
            return;
        }

        // CASE 3: Range Proof
        else if (tag == comms_GenericMessage_range_proof_request_tag) {
            spdlog::info("DEBUG: Found RangeProofRequest tag");
            std::vector<uint8_t> c1, c2;
            std::vector<std::vector<uint8_t>> squares(4);
            
            comms_RangeProofRequest msg = comms_RangeProofRequest_init_default;
            msg.c1.funcs.decode = decode_bytes; msg.c1.arg = &c1;
            msg.c2.funcs.decode = decode_bytes; msg.c2.arg = &c2;
            msg.sq0.funcs.decode = decode_bytes; msg.sq0.arg = &squares[0];
            msg.sq1.funcs.decode = decode_bytes; msg.sq1.arg = &squares[1];
            msg.sq2.funcs.decode = decode_bytes; msg.sq2.arg = &squares[2];
            msg.sq3.funcs.decode = decode_bytes; msg.sq3.arg = &squares[3];

            pb_istream_t substream;
            if (!pb_make_string_substream(&stream, &substream)) {
                 spdlog::error("RangeProof: Substream failed"); return;
            }
            if (!pb_decode(&substream, comms_RangeProofRequest_fields, &msg)) {
                 spdlog::error("RangeProof: Decode failed"); return;
            }
            pb_close_string_substream(&stream, &substream);

            spdlog::info("[Range] Request: [{}, {}]", msg.min_value, msg.max_value);
            
            bool ok = CryptoUtils::verify_range_proof_math(msg.min_value, msg.max_value, c1, c2, squares);
            if(ok) spdlog::info("[Range] VERIFICATION PASSED");
            else spdlog::error("[Range] VERIFICATION FAILED");

            comms_GenericMessage resp = comms_GenericMessage_init_zero;
            resp.which_payload = comms_GenericMessage_range_proof_response_tag;
            resp.payload.range_proof_response.success = ok;
            session->send_message(resp);
            return;
        }

        else {
            spdlog::warn("DEBUG: Skipping unknown tag: {}", tag);
            pb_skip_field(&stream, wire_type);
        }
    }
}