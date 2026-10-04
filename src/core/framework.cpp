#include "core/framework.h"
#include "core/module.h"
#include <iostream>
#include <filesystem>
#include <algorithm>
#include <thread>
#include <chrono>

namespace BlueBoy {

Framework::Framework(const std::string& config_path) {
    // Initialize logger
    logger_ = std::make_unique<Logger>("logs/blueboy.log", LogLevel::INFO);
    
    // Initialize config manager
    config_manager_ = std::make_unique<Config>();
    
    // Load configuration
    if (!config_path.empty()) {
        loadConfig(config_path);
    } else {
        // Set default configuration
        config_.output_directory = "output/";
        config_.log_level = "INFO";
        config_.verbose = false;
        config_.debug = false;
        config_.timeout = 30;
        config_.interface = "hci0";
    }
    
    // Initialize modules
    initializeModules();
    
    logger_->info("BlueBoy Framework initialized");
}

Framework::~Framework() {
    logger_->info("BlueBoy Framework shutting down");
}

bool Framework::loadConfig(const std::string& config_path) {
    if (!config_manager_->loadFromFile(config_path)) {
        logger_->error("Failed to load configuration from: " + config_path);
        return false;
    }
    
    config_ = config_manager_->getFrameworkConfig();
    
    // Update logger level
    if (config_.log_level == "DEBUG") {
        logger_->setLogLevel(LogLevel::DEBUG);
    } else if (config_.log_level == "WARNING") {
        logger_->setLogLevel(LogLevel::WARNING);
    } else if (config_.log_level == "ERROR") {
        logger_->setLogLevel(LogLevel::ERROR);
    }
    
    logger_->info("Configuration loaded successfully");
    return true;
}

void Framework::initializeModules() {
    // Get all available modules from factory
    auto available_modules = ModuleFactory::getAvailableModules();
    
    for (const auto& module_name : available_modules) {
        auto module = ModuleFactory::createModule(module_name);
        if (module) {
            modules_[module_name] = std::move(module);
            
            // Add to category mapping
            VulnCategory category = modules_[module_name]->getCategory();
            category_modules_[category].push_back(module_name);
            
            logger_->debug("Loaded module: " + module_name);
        }
    }
    
    logger_->info("Loaded " + std::to_string(modules_.size()) + " modules");
}

std::vector<std::string> Framework::listModules() const {
    std::vector<std::string> module_list;
    for (const auto& pair : modules_) {
        module_list.push_back(pair.first);
    }
    std::sort(module_list.begin(), module_list.end());
    return module_list;
}

std::vector<std::string> Framework::listCategories() const {
    std::vector<std::string> categories = {
        "reconnaissance",
        "exploitation", 
        "denial_of_service",
        "man_in_the_middle",
        "privilege_escalation",
        "persistence"
    };
    return categories;
}

ModuleResult Framework::runModule(const std::string& module_name, const BluetoothTarget& target) {
    ModuleResult result;
    result.success = false;
    result.execution_time = 0.0;
    
    auto it = modules_.find(module_name);
    if (it == modules_.end()) {
        result.message = "Module not found: " + module_name;
        logger_->error(result.message);
        return result;
    }
    
    auto& module = it->second;
    
    // Validate target
    if (!module->validate(target)) {
        result.message = "Target validation failed for module: " + module_name;
        logger_->error(result.message);
        return result;
    }
    
    logger_->info("Executing module: " + module_name + " against target: " + target.mac_address);
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    try {
        result = module->execute(target);
        
        auto end_time = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time);
        result.execution_time = duration.count() / 1000.0;
        
        if (result.success) {
            logger_->info("Module " + module_name + " executed successfully");
        } else {
            logger_->warning("Module " + module_name + " execution failed: " + result.message);
        }
        
    } catch (const std::exception& e) {
        result.success = false;
        result.message = "Exception during module execution: " + std::string(e.what());
        logger_->error(result.message);
    }
    
    return result;
}

std::vector<ModuleResult> Framework::runCategory(VulnCategory category, const BluetoothTarget& target) {
    std::vector<ModuleResult> results;
    
    auto it = category_modules_.find(category);
    if (it == category_modules_.end()) {
        logger_->warning("No modules found for category");
        return results;
    }
    
    const auto& module_names = it->second;
    logger_->info("Running " + std::to_string(module_names.size()) + " modules in category");
    
    for (const auto& module_name : module_names) {
        auto result = runModule(module_name, target);
        results.push_back(result);
        
        // Small delay between modules
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    return results;
}

std::vector<BluetoothTarget> Framework::scanTargets() {
    std::vector<BluetoothTarget> targets;
    
    logger_->info("Scanning for Bluetooth devices...");
    
    // Simulate device discovery (in real implementation, use BlueZ)
    BluetoothTarget target1;
    target1.mac_address = "00:11:22:33:44:55";
    target1.name = "Example Device 1";
    target1.device_class = "Phone";
    target1.rssi = -45;
    target1.paired = false;
    targets.push_back(target1);
    
    BluetoothTarget target2;
    target2.mac_address = "AA:BB:CC:DD:EE:FF";
    target2.name = "Example Device 2";
    target2.device_class = "Computer";
    target2.rssi = -60;
    target2.paired = true;
    targets.push_back(target2);
    
    logger_->info("Found " + std::to_string(targets.size()) + " devices");
    return targets;
}

bool Framework::validateTarget(const std::string& mac_address) {
    // Basic MAC address validation
    if (mac_address.length() != 17) return false;
    
    for (size_t i = 0; i < mac_address.length(); ++i) {
        if (i % 3 == 2) {
            if (mac_address[i] != ':') return false;
        } else {
            if (!std::isxdigit(mac_address[i])) return false;
        }
    }
    
    return true;
}

void Framework::interactiveMode() {
    displayBanner();
    std::cout << "\n[+] Modo interactivo iniciado" << std::endl;
    std::cout << "Escriba 'help' para ver comandos disponibles\n" << std::endl;
    
    std::string input;
    while (true) {
        std::cout << "blueboy> ";
        std::getline(std::cin, input);
        
        if (input == "exit" || input == "quit") {
            break;
        } else if (input == "help") {
            displayHelp();
        } else if (input == "list") {
            auto modules = listModules();
            std::cout << "\nMódulos disponibles:" << std::endl;
            for (const auto& module : modules) {
                std::cout << "  • " << module << std::endl;
            }
        } else if (input == "scan") {
            auto targets = scanTargets();
            std::cout << "\nDispositivos encontrados:" << std::endl;
            for (const auto& target : targets) {
                std::cout << "  • " << target.mac_address << " (" << target.name << ")" << std::endl;
            }
        } else if (input.empty()) {
            continue;
        } else {
            std::cout << "Comando desconocido: " << input << std::endl;
            std::cout << "Escriba 'help' para ver comandos disponibles" << std::endl;
        }
    }
    
    std::cout << "\n[+] Saliendo del modo interactivo" << std::endl;
}

void Framework::displayBanner() {
    std::cout << R"(
    ██████╗ ██╗     ██╗   ██╗███████╗██████╗  ██████╗ ██╗   ██╗
    ██╔══██╗██║     ██║   ██║██╔════╝██╔══██╗██╔═══██╗╚██╗ ██╔╝
    ██████╔╝██║     ██║   ██║█████╗  ██████╔╝██║   ██║ ╚████╔╝ 
    ██╔══██╗██║     ██║   ██║██╔══╝  ██╔══██╗██║   ██║  ╚██╔╝  
    ██████╔╝███████╗╚██████╔╝███████╗██████╔╝╚██████╔╝   ██║   
    ╚═════╝ ╚══════╝ ╚═════╝ ╚══════╝╚═════╝  ╚═════╝    ╚═╝   
    
    Framework de Vulnerabilidades Bluetooth v1.0
    Solo para Fines Educativos y Pruebas Autorizadas
    )" << std::endl;
}

void Framework::displayHelp() {
    std::cout << "\nComandos disponibles:" << std::endl;
    std::cout << "  help     - Mostrar esta ayuda" << std::endl;
    std::cout << "  list     - Listar módulos disponibles" << std::endl;
    std::cout << "  scan     - Escanear dispositivos Bluetooth" << std::endl;
    std::cout << "  exit     - Salir del modo interactivo" << std::endl;
    std::cout << "  quit     - Salir del modo interactivo" << std::endl;
}

} // namespace BlueBoy
