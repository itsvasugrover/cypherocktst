#include "server.hpp"
#include <iostream>
#include <vector>
#include "pb_decode.h"
#include "pb_encode.h"
#include "comms.pb.h"

void handle_client_message(const std::vector<uint8_t>& data, tcp::socket& socket) {
    std::cout << "Received " << data.size() << " bytes from client." << std::endl;

    pb_istream_t stream = pb_istream_from_buffer(data.data(), data.size());

    comms_GenericMessage message = comms_GenericMessage_init_zero;

    if (!pb_decode(&stream, comms_GenericMessage_fields, &message)) {
        std::cerr << "Protobuf Decode Failed: " << PB_GET_ERROR(&stream) << std::endl;
        return;
    }

    switch (message.which_payload) {
        case comms_GenericMessage_auth_init_tag:
            std::cout << "Type: Auth Init" << std::endl;
            break;
        case comms_GenericMessage_auth_response_tag:
            std::cout << "Type: Auth Verify" << std::endl;
            break;
        case comms_GenericMessage_range_proof_request_tag:
            std::cout << "Type: Range Proof Request" << std::endl;
            break;
        default:
            std::cout << "Unknown or Unimplemented Message Type" << std::endl;
    }
}