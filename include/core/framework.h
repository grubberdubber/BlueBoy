#ifndef FRAMEWORK_H
#define FRAMEWORK_H

#include "blueboy.h"
#include "module.h"
#include "logger.h"
#include "config.h"
#include <memory>
#include <unordered_map>

namespace BlueBoy {

class Framework {
public:
    Framework(const std::string& config_path = "");
    ~Framework();

    // Module management
    bool loadModule(const std::string& module_name);
    bool unloadModule(const std::string& module_name);
    std::vector<std::string> listModules() const;
    std::vector<std::string> listCategories() const;
    
    // Module execution
    ModuleResult runModule(const std::string& module_name, const BluetoothTarget& target);
    std::vector<ModuleResult> runCategory(VulnCategory category, const BluetoothTarget& target);
    
    // Interactive mode
    void interactiveMode();
    
    // Configuration
    bool loadConfig(const std::string& config_path);
    const FrameworkConfig& getConfig() const { return config_; }
    
    // Logging
    Logger& getLogger() { return *logger_; }
    
    // Target management
    std::vector<BluetoothTarget> scanTargets();
    bool validateTarget(const std::string& mac_address);

private:
    void initializeModules();
    void displayBanner();
    void displayHelp();
    
    std::unique_ptr<Logger> logger_;
    std::unique_ptr<Config> config_manager_;
    FrameworkConfig config_;
    
    std::unordered_map<std::string, std::unique_ptr<Module>> modules_;
    std::unordered_map<VulnCategory, std::vector<std::string>> category_modules_;
};

} // namespace BlueBoy

#endif // FRAMEWORK_H
