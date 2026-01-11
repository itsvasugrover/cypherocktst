#pragma once

#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <memory>
#include <vector>
#include <iostream>
#include "crypto.hpp"
#include "comms.pb.h"

using boost::asio::ip::tcp;

class Session : public std::enable_shared_from_this<Session> {
public:
    Session(tcp::socket socket);
    void start();
    void send_message(const comms_GenericMessage& msg);

private:
    void check_deadline();
    void read_header();
    void read_body(uint32_t length);
    void handle_message(const std::vector<uint8_t>& data);

    tcp::socket socket_;
    uint8_t length_buffer_[4];
    std::vector<uint8_t> data_;
    const static uint32_t SESSION_TIMEOUT_SECONDS = 60;

    // --- SESSION STATE ---
    uint32_t session_id_;
    bool is_authenticated_;
    boost::asio::steady_timer deadline_;
    std::vector<uint8_t> session_nonce_;
};

class Server {
public:
    Server(boost::asio::io_context& io_context, short port);

private:
    void do_accept();
    tcp::acceptor acceptor_;
};