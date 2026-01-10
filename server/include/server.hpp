#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <vector>
#include <iostream>

using boost::asio::ip::tcp;

void handle_client_message(const std::vector<uint8_t>& data, tcp::socket& socket);

// single connection with a client
class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket) : socket_(std::move(socket)) {}

    void start() {
        read_header();
    }

private:
    void read_header() {
        auto self(shared_from_this());
        boost::asio::async_read(socket_, boost::asio::buffer(length_buffer_, 4),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    uint32_t msg_len = 0;
                    std::memcpy(&msg_len, length_buffer_, 4);
                    
                    if (msg_len > 1024 * 1024) {
                        std::cerr << "Message too large, closing." << std::endl;
                        return; 
                    }
                    read_body(msg_len);
                }
            });
    }

    void read_body(uint32_t length) {
        auto self(shared_from_this());
        data_.resize(length);
        
        boost::asio::async_read(socket_, boost::asio::buffer(data_, length),
            [this, self](boost::system::error_code ec, std::size_t) {
                if (!ec) {
                    handle_client_message(data_, socket_);
                    read_header();
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