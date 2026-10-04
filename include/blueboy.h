#ifndef BLUEBOY_H
#define BLUEBOY_H

#include <string>
#include <vector>
#include <memory>
#include <map>

namespace BlueBoy {

// Forward declarations
class Framework;
class Module;
class Logger;
class Config;

// Vulnerability categories
enum class VulnCategory {
    RECONNAISSANCE,
    EXPLOITATION,
    DENIAL_OF_SERVICE,
    MAN_IN_THE_MIDDLE,
    PRIVILEGE_ESCALATION,
    PERSISTENCE
};

// Attack severity levels
enum class Severity {
    LOW,
    MEDIUM,
    HIGH,
    CRITICAL
};

// Module execution result
struct ModuleResult {
    bool success;
    std::string message;
    std::vector<std::string> data;
    double execution_time;
};

// Target device information
struct BluetoothTarget {
    std::string mac_address;
    std::string name;
    std::string device_class;
    std::vector<std::string> services;
    int rssi;
    bool paired;
};

// Framework configuration
struct FrameworkConfig {
    std::string output_directory;
    std::string log_level;
    bool verbose;
    bool debug;
    int timeout;
    std::string interface;
};

} // namespace BlueBoy

#endif // BLUEBOY_H
