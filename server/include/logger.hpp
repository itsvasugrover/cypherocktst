#pragma once

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <memory>
#include <vector>
#include <filesystem>

class Logger {
public:
    static void init() {
        std::filesystem::create_directories("logs");

        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::debug);
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");

        auto file_sink = std::make_shared<spdlog::sinks::basic_file_sink_mt>("logs/server.log", true);
        file_sink->set_level(spdlog::level::trace);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] %v");

        std::vector<spdlog::sink_ptr> sinks {console_sink, file_sink};
        auto logger = std::make_shared<spdlog::logger>("server", sinks.begin(), sinks.end());
        
        spdlog::set_default_logger(logger);
        spdlog::set_level(spdlog::level::debug);
        spdlog::flush_on(spdlog::level::debug);
    }
};