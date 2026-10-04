#ifndef LOGGER_H
#define LOGGER_H

#include <string>
#include <fstream>
#include <memory>
#include <mutex>

namespace BlueBoy {

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

class Logger {
public:
    Logger(const std::string& log_file = "", LogLevel level = LogLevel::INFO);
    ~Logger();

    void setLogLevel(LogLevel level) { log_level_ = level; }
    void setLogFile(const std::string& log_file);
    
    void debug(const std::string& message);
    void info(const std::string& message);
    void warning(const std::string& message);
    void error(const std::string& message);
    void critical(const std::string& message);
    
    void log(LogLevel level, const std::string& message);

private:
    void writeLog(LogLevel level, const std::string& message);
    std::string levelToString(LogLevel level) const;
    std::string getCurrentTimestamp() const;
    
    LogLevel log_level_;
    std::unique_ptr<std::ofstream> log_file_;
    std::mutex log_mutex_;
    bool console_output_;
};

} // namespace BlueBoy

#endif // LOGGER_H
