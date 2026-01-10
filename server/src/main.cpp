#include <iostream>
#include <boost/asio.hpp>
#include "pb_encode.h"
#include "pb_decode.h"
#include "comms.pb.h"
#include "secp256k1.h" // From trezor-crypto

int main() {
    std::cout << "Cypherock Server Starting..." << std::endl;
    std::cout << "Boost Asio Version: " << BOOST_ASIO_VERSION << std::endl;
    
    // Quick check if Trezor headers are found
    const curve_point *G = &secp256k1.G;
    std::cout << "Trezor Crypto Linked. SECP256k1 G point accessed." << std::endl;

    // Basic Protobuf Encoding Example
    {
        comms_GenericMessage msg = comms_GenericMessage_init_zero;
        msg.which_payload = comms_GenericMessage_auth_status_tag;
        msg.payload.auth_status.authenticated = true;

        uint8_t buffer[256];
        pb_ostream_t stream = pb_ostream_from_buffer(buffer, sizeof(buffer));
        bool encode_status = pb_encode(&stream, comms_GenericMessage_fields, &msg);
        size_t encoded_size = stream.bytes_written;

        std::cout << "Basic Protobuf Encode Status: " << (encode_status ? "Success" : "Failed") << std::endl;
        std::cout << "Encoded Size: " << encoded_size << " bytes" << std::endl;
    }

    return 0;
}