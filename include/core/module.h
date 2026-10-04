#ifndef MODULE_H
#define MODULE_H

#include "blueboy.h"
#include <string>
#include <vector>
#include <functional>
#include <map>

namespace BlueBoy {

class Module {
public:
    Module(const std::string& name, VulnCategory category, Severity severity);
    virtual ~Module() = default;

    // Module information
    const std::string& getName() const { return name_; }
    VulnCategory getCategory() const { return category_; }
    Severity getSeverity() const { return severity_; }
    const std::string& getDescription() const { return description_; }
    const std::vector<std::string>& getReferences() const { return references_; }

    // Module execution
    virtual ModuleResult execute(const BluetoothTarget& target) = 0;
    virtual bool validate(const BluetoothTarget& target) = 0;
    
    // Module configuration
    virtual void setOption(const std::string& key, const std::string& value);
    virtual std::string getOption(const std::string& key) const;
    virtual std::vector<std::string> getRequiredOptions() const;

protected:
    void setDescription(const std::string& description) { description_ = description; }
    void addReference(const std::string& reference) { references_.push_back(reference); }
    
    // Utility functions for modules
    bool isValidMacAddress(const std::string& mac) const;
    std::string formatMacAddress(const std::string& mac) const;
    bool pingTarget(const BluetoothTarget& target) const;
    
private:
    std::string name_;
    VulnCategory category_;
    Severity severity_;
    std::string description_;
    std::vector<std::string> references_;
    std::map<std::string, std::string> options_;
};

// Module factory for dynamic loading
class ModuleFactory {
public:
    static std::unique_ptr<Module> createModule(const std::string& module_name);
    static std::vector<std::string> getAvailableModules();
    static void registerModule(const std::string& name, 
                              std::function<std::unique_ptr<Module>()> creator);

private:
    static std::map<std::string, std::function<std::unique_ptr<Module>()>> creators_;
};

// Macro for easy module registration
#define REGISTER_MODULE(name, class_name) \
    static bool registered_##class_name = []() { \
        ModuleFactory::registerModule(name, []() { \
            return std::make_unique<class_name>(); \
        }); \
        return true; \
    }();

} // namespace BlueBoy

#endif // MODULE_H
