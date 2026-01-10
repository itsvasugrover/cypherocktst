#include <iostream>
#include <boost/asio/signal_set.hpp>
#include "server.hpp"
#include "logger.hpp"

int main(int argc, char* argv[]) {
    try {
        // Initialize Logger
        Logger::init();
        int port = 8080;

        // Parse command-line arguments (unchanged)
        for(int i = 1; i < argc; i++) {
            std::string arg = argv[i];
            if (arg == "--port" && i+1 < argc) {
                try {
                    port = std::stoi(argv[++i]);
                } catch (const std::exception&) {
                    spdlog::warn("Invalid port value '{}', using default port 8080", argv[i]);
                }
            } else {
                spdlog::warn("Unknown argument '{}', ignoring", arg);
            }
        }
  
        spdlog::info("--- Server Starting ---");
        spdlog::info("Listening on port {}", port);
  
        boost::asio::io_context io_context;
        Server server(io_context, port);
          
        // Set up signal handling for graceful shutdown on SIGINT (Ctrl+C)
        boost::asio::signal_set signals(io_context, SIGINT);
        signals.async_wait([&](const boost::system::error_code& ec, int signal_number) {
            if (!ec) {
                spdlog::info("Signal {} received. Shutting down gracefully...", signal_number);
                io_context.stop();
            }
        });
        
        spdlog::info("Press Ctrl+C to stop the server.");
        io_context.run();
        spdlog::info("--- Server Stopped ---");
        spdlog::shutdown();
    } catch (std::exception& e) {
        // Fallback to stderr if spdlog fails or isn't init yet
        std::cerr << "CRITICAL EXCEPTION: " << e.what() << "\n";
    }
  
    return 0;
}
