#include "core/module.h"
#include <regex>
#include <algorithm>
#include <cctype>

namespace BlueBoy {

// Static member initialization
std::map<std::string, std::function<std::unique_ptr<Module>()>> ModuleFactory::creators_;

Module::Module(const std::string& name, VulnCategory category, Severity severity)
    : name_(name), category_(category), severity_(severity) {
}

void Module::setOption(const std::string& key, const std::string& value) {
    options_[key] = value;
}

std::string Module::getOption(const std::string& key) const {
    auto it = options_.find(key);
    return (it != options_.end()) ? it->second : "";
}

std::vector<std::string> Module::getRequiredOptions() const {
    // Default implementation - modules can override
    return {};
}

bool Module::isValidMacAddress(const std::string& mac) const {
    std::regex mac_regex("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$");
    return std::regex_match(mac, mac_regex);
}

std::string Module::formatMacAddress(const std::string& mac) const {
    std::string formatted = mac;
    std::transform(formatted.begin(), formatted.end(), formatted.begin(), ::toupper);
    
    // Replace any separators with colons
    std::replace(formatted.begin(), formatted.end(), '-', ':');
    
    return formatted;
}

bool Module::pingTarget(const BluetoothTarget& target) const {
    // Simulate ping - in real implementation, use L2CAP ping
    return !target.mac_address.empty();
}

// ModuleFactory implementation
std::unique_ptr<Module> ModuleFactory::createModule(const std::string& module_name) {
    auto it = creators_.find(module_name);
    if (it != creators_.end()) {
        return it->second();
    }
    return nullptr;
}

std::vector<std::string> ModuleFactory::getAvailableModules() {
    std::vector<std::string> modules;
    for (const auto& pair : creators_) {
        modules.push_back(pair.first);
    }
    return modules;
}

void ModuleFactory::registerModule(const std::string& name, 
                                  std::function<std::unique_ptr<Module>()> creator) {
    creators_[name] = creator;
}

} // namespace BlueBoy
