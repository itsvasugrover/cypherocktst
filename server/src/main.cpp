#include <iostream>
#include <boost/asio.hpp>
#include "server.hpp"

int main(int argc, char* argv[]) {
    try {
        std::cout << "Starting Server on port 8080..." << std::endl;
        
        boost::asio::io_context io_context;
        Server server(io_context, 8080);
        
        io_context.run(); // Start the IO context event loop to accept incoming connections
    } catch (std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
    }

    return 0;
}