#include "core/logger.h"
#include <chrono>
#include <ctime>
#include <iomanip>

namespace blueboy {

Logger &Logger::instance() {
  static Logger l;
  return l;
}

const char *Logger::tag(LogLevel lvl) {
  switch (lvl) {
  case LogLevel::TRACE:
    return "TRACE";
  case LogLevel::DEBUG:
    return "DEBUG";
  case LogLevel::INFO:
    return "INFO";
  case LogLevel::WARN:
    return "WARN";
  case LogLevel::ERROR:
    return "ERROR";
  case LogLevel::FATAL:
    return "FATAL";
  }
  return "?";
}

void Logger::set_level(LogLevel lvl) {
  std::lock_guard<std::mutex> g(mtx_);
  level_ = lvl;
}

void Logger::set_file(const std::string &path) {
  std::lock_guard<std::mutex> g(mtx_);
  file_.open(path, std::ios::app);
}

void Logger::log(LogLevel lvl, const std::string &msg) {
  std::lock_guard<std::mutex> g(mtx_);
  if (static_cast<int>(lvl) < static_cast<int>(level_))
    return;

  auto now = std::chrono::system_clock::now();
  std::time_t t = std::chrono::system_clock::to_time_t(now);
  auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                now.time_since_epoch()) %
            1000;

  std::tm tm{};
  localtime_r(&t, &tm);
  std::ostringstream ts;
  ts << std::put_time(&tm, "%Y-%m-%d %H:%M:%S") << '.' << std::setfill('0')
     << std::setw(3) << ms.count();

  std::ostringstream line;
  line << "[" << ts.str() << "] [" << tag(lvl) << "] " << msg;

  if (console_)
    std::cout << line.str() << "\n" << std::flush;
  if (file_.is_open())
    file_ << line.str() << "\n" << std::flush;
}

} // namespace blueboy
