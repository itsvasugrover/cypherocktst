#include "server.hpp"
#include <string>
#include "pb_decode.h"
#include "pb_encode.h"
#include "keys.hpp"
#include "logger.hpp"

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

Session::Session(tcp::socket socket) 
    : socket_(std::move(socket)), deadline_(socket_.get_executor()), is_authenticated_(false) {
    // Generate a unique ID for this session (just for logging)
    static uint32_t id_counter = 0;
    session_id_ = ++id_counter;
    spdlog::info("[Session {}] Connected from {}", session_id_, socket_.remote_endpoint().address().to_string());
}

void Session::start() {
    deadline_.expires_after(std::chrono::seconds(SESSION_TIMEOUT_SECONDS));
    check_deadline();
    read_header();
}

void Session::check_deadline() {
    auto self(shared_from_this());
    if (deadline_.expiry() <= boost::asio::steady_timer::clock_type::now()) {
        socket_.close();
        deadline_.cancel(); 
        spdlog::warn("[Session {}] Connection Timed Out.", session_id_);
        return;
    }

    deadline_.async_wait([this, self](boost::system::error_code ec) {
        if (ec != boost::asio::error::operation_aborted) {
            check_deadline();
        }
    });
}

void Session::read_header() {
    deadline_.expires_after(std::chrono::seconds(SESSION_TIMEOUT_SECONDS));
    auto self(shared_from_this());
    boost::asio::async_read(socket_, boost::asio::buffer(length_buffer_, 4),
        [this, self](boost::system::error_code ec, std::size_t) {
            if (!ec) {
                uint32_t msg_len = length_buffer_[0] | (length_buffer_[1] << 8) | (length_buffer_[2] << 16) | (length_buffer_[3] << 24);
                
                if (msg_len > 2 * 1024 * 1024) { // 2MB Limit (DoS Protection)
                    spdlog::error("[Session {}] Message too large ({} bytes). Closing.", session_id_, msg_len);
                    return; 
                }
                read_body(msg_len);
            } else if (ec != boost::asio::error::eof) {
                spdlog::error("[Session {}] Header Read Error: {}", session_id_, ec.message());
            } else {
                spdlog::info("[Session {}] Disconnected.", session_id_);
            }
        });
}

void Session::read_body(uint32_t length) {
    auto self(shared_from_this());
    data_.resize(length);
    
    boost::asio::async_read(socket_, boost::asio::buffer(data_, length),
        [this, self](boost::system::error_code ec, std::size_t) {
            if (!ec) {
                handle_message(data_);
                // LOOP: Wait for the next message!
                read_header(); 
            } else {
                spdlog::error("[Session {}] Body Read Error: {}", session_id_, ec.message());
            }
        });
}

void Session::send_message(const comms_GenericMessage& msg) {
    pb_ostream_t sizer = PB_OSTREAM_SIZING;
    if (!pb_encode(&sizer, comms_GenericMessage_fields, &msg)) return;
    size_t size = sizer.bytes_written;

    std::vector<uint8_t> body(size);
    pb_ostream_t stream = pb_ostream_from_buffer(body.data(), size);
    if (!pb_encode(&stream, comms_GenericMessage_fields, &msg)) return;

    uint32_t len_le = size;
    std::vector<uint8_t> header(4);
    header[0] = len_le & 0xFF;
    header[1] = (len_le >> 8) & 0xFF;
    header[2] = (len_le >> 16) & 0xFF;
    header[3] = (len_le >> 24) & 0xFF;

    auto self(shared_from_this());
    auto buffer_ptr = std::make_shared<std::vector<uint8_t>>(header);
    buffer_ptr->insert(buffer_ptr->end(), body.begin(), body.end());

    boost::asio::async_write(socket_, boost::asio::buffer(*buffer_ptr),
        [this, self, buffer_ptr](boost::system::error_code ec, std::size_t) {
            if (ec) spdlog::error("[Session {}] Write Failed: {}", session_id_, ec.message());
    });
}

void Session::handle_message(const std::vector<uint8_t>& data) {
    pb_istream_t stream = pb_istream_from_buffer(data.data(), data.size());
    pb_wire_type_t wire_type;
    uint32_t tag;
    bool eof;

    while (pb_decode_tag(&stream, &wire_type, &tag, &eof)) {
        
        // AUTH INIT
        if (tag == comms_GenericMessage_auth_init_tag) {
            if (is_authenticated_) {
                spdlog::warn("[Session {}] Client already authenticated. Ignoring Init.", session_id_);
                return;
            }

            std::string serial_id;
            std::vector<uint8_t> signature;
            bool is_valid = true;
            comms_AuthInit msg = comms_AuthInit_init_default;
            msg.serial_id.funcs.decode = decode_string; msg.serial_id.arg = &serial_id;
            msg.signature.funcs.decode = decode_bytes; msg.signature.arg = &signature;

            pb_istream_t substream;
            if (!pb_make_string_substream(&stream, &substream) || !pb_decode(&substream, comms_AuthInit_fields, &msg)) return;
            pb_close_string_substream(&stream, &substream);

            spdlog::info("[Session {}] Auth Request: Serial={}", session_id_, serial_id);

            // Verify Identity
            auto client_pub = CryptoUtils::load_public_key_from_pem(CLIENT_PUB_KEY);
            if (!CryptoUtils::verify_signature(client_pub, CryptoUtils::sha256(serial_id), signature)) {
                spdlog::warn("[Session {}] Auth Failed: Bad Identity Signature", session_id_);
                is_valid = false;
            }

            if (!is_valid) {
                comms_GenericMessage resp = comms_GenericMessage_init_zero;
                resp.which_payload = comms_GenericMessage_auth_status_tag;
                resp.payload.auth_status.authenticated = false;
                send_message(resp);
                return;
            }

            // Generate Challenge
            session_nonce_ = CryptoUtils::generate_random_bytes(32);
            
            auto server_priv = CryptoUtils::load_private_key_from_pem(SERVER_PRIV_KEY);
            auto sig = CryptoUtils::sign_data(server_priv, CryptoUtils::sha256(session_nonce_));

            comms_GenericMessage resp = comms_GenericMessage_init_zero;
            resp.which_payload = comms_GenericMessage_auth_challenge_tag;
            resp.payload.auth_challenge.random_number.funcs.encode = encode_bytes;
            resp.payload.auth_challenge.random_number.arg = &session_nonce_;
            resp.payload.auth_challenge.server_signature.funcs.encode = encode_bytes;
            resp.payload.auth_challenge.server_signature.arg = &sig;
            
            send_message(resp);
            return;
        }

        // AUTH RESPONSE
        else if (tag == comms_GenericMessage_auth_response_tag) {
            std::vector<uint8_t> signature;
            comms_AuthResponse msg = comms_AuthResponse_init_default;
            msg.signature.funcs.decode = decode_bytes; msg.signature.arg = &signature;

            pb_istream_t substream;
            if (!pb_make_string_substream(&stream, &substream) || !pb_decode(&substream, comms_AuthResponse_fields, &msg)) return;
            pb_close_string_substream(&stream, &substream);

            if (session_nonce_.empty()) {
                spdlog::warn("[Session {}] Unexpected AuthResponse (No nonce)", session_id_);
                return;
            }

            auto client_pub = CryptoUtils::load_public_key_from_pem(CLIENT_PUB_KEY);
            bool ok = CryptoUtils::verify_signature(client_pub, CryptoUtils::sha256(session_nonce_), signature);
            
            if (ok) {
                is_authenticated_ = true;
                spdlog::info("[Session {}] AUTHENTICATED SUCCESSFULLY.", session_id_);
            } else {
                spdlog::warn("[Session {}] Auth Failed: Bad Challenge Signature", session_id_);
            }

            comms_GenericMessage resp = comms_GenericMessage_init_zero;
            resp.which_payload = comms_GenericMessage_auth_status_tag;
            resp.payload.auth_status.authenticated = ok;
            send_message(resp);
            return;
        }

        // RANGE PROOF
        else if (tag == comms_GenericMessage_range_proof_request_tag) {
            // SECURITY CHECK: State Machine
            if (!is_authenticated_) {
                spdlog::warn("[Session {}] ATTACK ATTEMPT: Range Proof request from unauthenticated client.", session_id_);
                // We can close connection here to be strict
                socket_.close();
                return;
            }

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
            if (!pb_make_string_substream(&stream, &substream) || !pb_decode(&substream, comms_RangeProofRequest_fields, &msg)) return;
            pb_close_string_substream(&stream, &substream);
            
            if (msg.min_value > msg.max_value) {
                spdlog::warn("[Session {}] Invalid Range Proof request: min > max ({} > {})", session_id_, msg.min_value, msg.max_value);
                comms_GenericMessage resp = comms_GenericMessage_init_zero;
                resp.which_payload = comms_GenericMessage_range_proof_response_tag;
                resp.payload.range_proof_response.success = false;
                send_message(resp);
                return;
            }

            spdlog::info("[Session {}] Verifying Range Proof [{}, {}]...", session_id_, msg.min_value, msg.max_value);
            
            bool ok = CryptoUtils::verify_range_proof_math(msg.min_value, msg.max_value, c1, c2, squares);
            
            if(ok) spdlog::info("[Session {}] Proof VALID.", session_id_);
            else   spdlog::warn("[Session {}] Proof INVALID.", session_id_);

            comms_GenericMessage resp = comms_GenericMessage_init_zero;
            resp.which_payload = comms_GenericMessage_range_proof_response_tag;
            resp.payload.range_proof_response.success = ok;
            send_message(resp);
            return;
        }
        else {
            pb_skip_field(&stream, wire_type);
        }
    }
}

// Server implementation remains simple
Server::Server(boost::asio::io_context& io_context, short port)
    : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
    spdlog::info("Server listening on port {}", port);
    do_accept();
}

void Server::do_accept() {
    acceptor_.async_accept(
        [this](boost::system::error_code ec, tcp::socket socket) {
            if (!ec) {
                std::make_shared<Session>(std::move(socket))->start();
            }
            do_accept();
        });
}