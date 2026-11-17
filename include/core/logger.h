#pragma once
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace blueboy {

enum class LogLevel { TRACE, DEBUG, INFO, WARN, ERROR, FATAL };

class Logger {
public:
  static Logger &instance();

  void set_level(LogLevel lvl);
  void set_file(const std::string &path);
  void enable_console(bool on) { console_ = on; }

  void log(LogLevel lvl, const std::string &msg);

private:
  Logger() = default;
  static const char *tag(LogLevel lvl);

  std::mutex mtx_;
  std::ofstream file_;
  LogLevel level_ = LogLevel::INFO;
  bool console_ = true;
};

} // namespace blueboy

#define BB_LOG(LVL, ...)                                                       \
  do {                                                                         \
    std::ostringstream _bb_o;                                                  \
    _bb_o << __VA_ARGS__;                                                      \
    ::blueboy::Logger::instance().log((LVL), _bb_o.str());                     \
  } while (0)

#define LOG_TRACE(...) BB_LOG(::blueboy::LogLevel::TRACE, __VA_ARGS__)
#define LOG_DEBUG(...) BB_LOG(::blueboy::LogLevel::DEBUG, __VA_ARGS__)
#define LOG_INFO(...) BB_LOG(::blueboy::LogLevel::INFO, __VA_ARGS__)
#define LOG_WARN(...) BB_LOG(::blueboy::LogLevel::WARN, __VA_ARGS__)
#define LOG_ERROR(...) BB_LOG(::blueboy::LogLevel::ERROR, __VA_ARGS__)
#define LOG_FATAL(...) BB_LOG(::blueboy::LogLevel::FATAL, __VA_ARGS__)
