#ifndef CONFIG_H
#define CONFIG_H

#include "blueboy.h"
#include <string>
#include <map>

namespace BlueBoy {

class Config {
public:
    Config();
    ~Config();

    bool loadFromFile(const std::string& config_path);
    bool saveToFile(const std::string& config_path) const;
    
    // Configuration getters
    std::string getString(const std::string& key, const std::string& default_value = "") const;
    int getInt(const std::string& key, int default_value = 0) const;
    bool getBool(const std::string& key, bool default_value = false) const;
    double getDouble(const std::string& key, double default_value = 0.0) const;
    
    // Configuration setters
    void setString(const std::string& key, const std::string& value);
    void setInt(const std::string& key, int value);
    void setBool(const std::string& key, bool value);
    void setDouble(const std::string& key, double value);
    
    // Framework configuration
    FrameworkConfig getFrameworkConfig() const;
    void setFrameworkConfig(const FrameworkConfig& config);
    
    // Validation
    bool validateConfig() const;
    std::vector<std::string> getValidationErrors() const;

private:
    void setDefaults();
    std::string trim(const std::string& str) const;
    
    std::map<std::string, std::string> config_values_;
    mutable std::vector<std::string> validation_errors_;
};

} // namespace BlueBoy

#endif // CONFIG_H
