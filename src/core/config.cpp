#include "core/config.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>

namespace BlueBoy {

Config::Config() {
    setDefaults();
}

Config::~Config() = default;

void Config::setDefaults() {
    config_values_["output_directory"] = "output/";
    config_values_["log_level"] = "INFO";
    config_values_["verbose"] = "false";
    config_values_["debug"] = "false";
    config_values_["timeout"] = "30";
    config_values_["interface"] = "hci0";
    config_values_["max_threads"] = "4";
    config_values_["retry_count"] = "3";
    config_values_["delay_between_modules"] = "100";
}

bool Config::loadFromFile(const std::string& config_path) {
    std::ifstream file(config_path);
    if (!file.is_open()) {
        return false;
    }
    
    std::string line;
    while (std::getline(file, line)) {
        line = trim(line);
        
        // Skip empty lines and comments
        if (line.empty() || line[0] == '#') {
            continue;
        }
        
        // Parse key=value pairs
        size_t equals_pos = line.find('=');
        if (equals_pos != std::string::npos) {
            std::string key = trim(line.substr(0, equals_pos));
            std::string value = trim(line.substr(equals_pos + 1));
            
            // Remove quotes if present
            if (value.length() >= 2 && value[0] == '"' && value.back() == '"') {
                value = value.substr(1, value.length() - 2);
            }
            
            config_values_[key] = value;
        }
    }
    
    return true;
}

bool Config::saveToFile(const std::string& config_path) const {
    // Create directory if it doesn't exist
    std::filesystem::path file_path(config_path);
    if (file_path.has_parent_path()) {
        std::filesystem::create_directories(file_path.parent_path());
    }
    
    std::ofstream file(config_path);
    if (!file.is_open()) {
        return false;
    }
    
    file << "# BlueBoy Framework Configuration\n";
    file << "# Generated automatically\n\n";
    
    for (const auto& pair : config_values_) {
        file << pair.first << "=" << pair.second << "\n";
    }
    
    return true;
}

std::string Config::getString(const std::string& key, const std::string& default_value) const {
    auto it = config_values_.find(key);
    return (it != config_values_.end()) ? it->second : default_value;
}

int Config::getInt(const std::string& key, int default_value) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        try {
            return std::stoi(it->second);
        } catch (const std::exception&) {
            return default_value;
        }
    }
    return default_value;
}

bool Config::getBool(const std::string& key, bool default_value) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        std::string value = it->second;
        std::transform(value.begin(), value.end(), value.begin(), ::tolower);
        return (value == "true" || value == "1" || value == "yes");
    }
    return default_value;
}

double Config::getDouble(const std::string& key, double default_value) const {
    auto it = config_values_.find(key);
    if (it != config_values_.end()) {
        try {
            return std::stod(it->second);
        } catch (const std::exception&) {
            return default_value;
        }
    }
    return default_value;
}

void Config::setString(const std::string& key, const std::string& value) {
    config_values_[key] = value;
}

void Config::setInt(const std::string& key, int value) {
    config_values_[key] = std::to_string(value);
}

void Config::setBool(const std::string& key, bool value) {
    config_values_[key] = value ? "true" : "false";
}

void Config::setDouble(const std::string& key, double value) {
    config_values_[key] = std::to_string(value);
}

FrameworkConfig Config::getFrameworkConfig() const {
    FrameworkConfig config;
    config.output_directory = getString("output_directory", "output/");
    config.log_level = getString("log_level", "INFO");
    config.verbose = getBool("verbose", false);
    config.debug = getBool("debug", false);
    config.timeout = getInt("timeout", 30);
    config.interface = getString("interface", "hci0");
    return config;
}

void Config::setFrameworkConfig(const FrameworkConfig& config) {
    setString("output_directory", config.output_directory);
    setString("log_level", config.log_level);
    setBool("verbose", config.verbose);
    setBool("debug", config.debug);
    setInt("timeout", config.timeout);
    setString("interface", config.interface);
}

bool Config::validateConfig() const {
    validation_errors_.clear();
    
    // Validate output directory
    std::string output_dir = getString("output_directory");
    if (output_dir.empty()) {
        validation_errors_.push_back("output_directory cannot be empty");
    }
    
    // Validate log level
    std::string log_level = getString("log_level");
    if (log_level != "DEBUG" && log_level != "INFO" && 
        log_level != "WARNING" && log_level != "ERROR" && 
        log_level != "CRITICAL") {
        validation_errors_.push_back("Invalid log_level: " + log_level);
    }
    
    // Validate timeout
    int timeout = getInt("timeout");
    if (timeout <= 0 || timeout > 3600) {
        validation_errors_.push_back("timeout must be between 1 and 3600 seconds");
    }
    
    // Validate interface
    std::string interface = getString("interface");
    if (interface.empty()) {
        validation_errors_.push_back("interface cannot be empty");
    }
    
    return validation_errors_.empty();
}

std::vector<std::string> Config::getValidationErrors() const {
    return validation_errors_;
}

std::string Config::trim(const std::string& str) const {
    size_t start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return "";
    }
    
    size_t end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

} // namespace BlueBoy
