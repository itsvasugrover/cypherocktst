#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <iostream>
#include "crypto.hpp"
#include "comms.pb.h"
#include "pb_encode.h"
#include "logger.hpp"

using boost::asio::ip::tcp;

class Session;
void handle_client_message(const std::vector<uint8_t>& data, std::shared_ptr<Session> session);

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket) : socket_(std::move(socket)) {}

    void start() {
        read_header();
    }

void send_message(const comms_GenericMessage& msg) {
        // IMPORTANT: Do not use pb_ostream_from_buffer(NULL, 0) for sizing!!! Spent hours trying to figure this out.
        pb_ostream_t sizer = PB_OSTREAM_SIZING;
        
        if (!pb_encode(&sizer, comms_GenericMessage_fields, &msg)) {
             spdlog::error("Encode Error (Sizing): {}", PB_GET_ERROR(&sizer));
             return;
        }
        size_t size = sizer.bytes_written;
        spdlog::info("DEBUG: Encoded message size: {} bytes", size);

        std::vector<uint8_t> body(size);
        pb_ostream_t stream = pb_ostream_from_buffer(body.data(), size);
        if (!pb_encode(&stream, comms_GenericMessage_fields, &msg)) {
             spdlog::error("Encode Error (Writing): {}", PB_GET_ERROR(&stream));
             return;
        }

        uint32_t len_le = size;
        std::vector<uint8_t> header(4);
        header[0] = len_le & 0xFF;
        header[1] = (len_le >> 8) & 0xFF;
        header[2] = (len_le >> 16) & 0xFF;
        header[3] = (len_le >> 24) & 0xFF;

        auto self(shared_from_this());
        
        auto buffer_ptr = std::make_shared<std::vector<uint8_t>>(header);
        buffer_ptr->insert(buffer_ptr->end(), body.begin(), body.end());

        spdlog::info("DEBUG: Sending {} total bytes to client...", buffer_ptr->size());

        boost::asio::async_write(socket_, boost::asio::buffer(*buffer_ptr),
            [this, self, buffer_ptr](boost::system::error_code ec, std::size_t bytes_sent) {
                if (ec) {
                    spdlog::error("Socket Write Failed: {}", ec.message());
                } else {
                    spdlog::info("DEBUG: Successfully sent {} bytes", bytes_sent);
                }
        });
    }

private:
    void read_header() {
        auto self(shared_from_this());
        boost::asio::async_read(socket_, boost::asio::buffer(length_buffer_, 4),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    uint32_t msg_len = 0;
                    msg_len = length_buffer_[0] | (length_buffer_[1] << 8) | (length_buffer_[2] << 16) | (length_buffer_[3] << 24);
                    
                    spdlog::info("DEBUG: Header received. Expecting body: {} bytes", msg_len);

                    if (msg_len > 1024 * 1024) { 
                        spdlog::error("Message too large, closing.");
                        return; 
                    }
                    read_body(msg_len);
                } else {
                    if(ec != boost::asio::error::eof)
                        spdlog::error("Read Header Failed: {}", ec.message());
                }
            });
    }

    void read_body(uint32_t length) {
        auto self(shared_from_this());
        data_.resize(length);
        
        boost::asio::async_read(socket_, boost::asio::buffer(data_, length),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    handle_client_message(data_, self);
                    read_header(); // Loop
                } else {
                    spdlog::error("Read Body Failed: {}", ec.message());
                }
            });
    }

    tcp::socket socket_;
    uint8_t length_buffer_[4];
    std::vector<uint8_t> data_;
};

class Server {
public:
    Server(boost::asio::io_context& io_context, short port)
        : acceptor_(io_context, tcp::endpoint(tcp::v4(), port)) {
        do_accept();
    }

private:
    void do_accept() {
        acceptor_.async_accept(
            [this](boost::system::error_code ec, tcp::socket socket) {
                if (!ec) {
                    std::make_shared<Session>(std::move(socket))->start();
                }
                do_accept();
            });
    }

    tcp::acceptor acceptor_;
};