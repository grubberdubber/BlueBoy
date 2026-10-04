#include "blueboy.h"
#include "core/framework.h"
#include <iostream>
#include <boost/program_options.hpp>
#include <signal.h>

using namespace BlueBoy;
namespace po = boost::program_options;

// Global framework instance for signal handling
std::unique_ptr<Framework> g_framework;

void signalHandler(int signal) {
    std::cout << "\n[!] Interrupted by user (signal " << signal << ")" << std::endl;
    exit(1);
}

void displayBanner() {
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

int main(int argc, char* argv[]) {
    // Setup signal handlers
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    try {
        // Command line options
        po::options_description desc("Opciones disponibles");
        desc.add_options()
            ("help,h", "Mostrar ayuda")
            ("list-modules,l", "Listar todos los módulos disponibles")
            ("list-categories,c", "Listar categorías de vulnerabilidades")
            ("interactive,i", "Iniciar modo interactivo")
            ("module,m", po::value<std::string>(), "Especificar módulo de vulnerabilidad a ejecutar")
            ("target,t", po::value<std::string>(), "Dirección MAC del dispositivo objetivo")
            ("category", po::value<std::string>(), "Ejecutar todos los módulos de la categoría especificada")
            ("config", po::value<std::string>()->default_value("config/default.conf"), "Ruta del archivo de configuración")
            ("output,o", po::value<std::string>()->default_value("output/"), "Directorio de salida para resultados")
            ("verbose,v", "Habilitar salida detallada")
            ("debug,d", "Habilitar modo debug")
            ("scan,s", "Escanear dispositivos Bluetooth cercanos")
            ("interface", po::value<std::string>()->default_value("hci0"), "Interfaz Bluetooth a usar");

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        // Show help
        if (vm.count("help")) {
            displayBanner();
            std::cout << desc << std::endl;
            return 0;
        }

        // Display banner for most operations
        if (!vm.count("list-modules") && !vm.count("list-categories")) {
            displayBanner();
        }

        // Initialize framework
        g_framework = std::make_unique<Framework>(vm["config"].as<std::string>());

        // Handle different modes
        if (vm.count("list-modules")) {
            auto modules = g_framework->listModules();
            std::cout << "\n[+] Módulos disponibles (" << modules.size() << "):\n" << std::endl;
            for (const auto& module : modules) {
                std::cout << "  • " << module << std::endl;
            }
        }
        else if (vm.count("list-categories")) {
            auto categories = g_framework->listCategories();
            std::cout << "\n[+] Categorías disponibles:\n" << std::endl;
            for (const auto& category : categories) {
                std::cout << "  • " << category << std::endl;
            }
        }
        else if (vm.count("scan")) {
            std::cout << "[+] Escaneando dispositivos Bluetooth..." << std::endl;
            auto targets = g_framework->scanTargets();
            std::cout << "\n[+] Dispositivos encontrados (" << targets.size() << "):\n" << std::endl;
            for (const auto& target : targets) {
                std::cout << "  • " << target.mac_address << " (" << target.name << ")" << std::endl;
            }
        }
        else if (vm.count("interactive")) {
            g_framework->interactiveMode();
        }
        else if (vm.count("module")) {
            if (!vm.count("target")) {
                std::cerr << "[!] Error: --target es requerido cuando se usa --module" << std::endl;
                return 1;
            }
            
            std::string module_name = vm["module"].as<std::string>();
            std::string target_mac = vm["target"].as<std::string>();
            
            if (!g_framework->validateTarget(target_mac)) {
                std::cerr << "[!] Error: Dirección MAC objetivo inválida" << std::endl;
                return 1;
            }
            
            BluetoothTarget target;
            target.mac_address = target_mac;
            
            std::cout << "[+] Ejecutando módulo: " << module_name << std::endl;
            std::cout << "[+] Objetivo: " << target_mac << std::endl;
            
            auto result = g_framework->runModule(module_name, target);
            
            if (result.success) {
                std::cout << "[+] Módulo ejecutado exitosamente" << std::endl;
                std::cout << "[+] Tiempo de ejecución: " << result.execution_time << "s" << std::endl;
                if (!result.message.empty()) {
                    std::cout << "[+] Resultado: " << result.message << std::endl;
                }
            } else {
                std::cerr << "[!] Error ejecutando módulo: " << result.message << std::endl;
                return 1;
            }
        }
        else if (vm.count("category")) {
            if (!vm.count("target")) {
                std::cerr << "[!] Error: --target es requerido cuando se usa --category" << std::endl;
                return 1;
            }
            
            std::string category_name = vm["category"].as<std::string>();
            std::string target_mac = vm["target"].as<std::string>();
            
            // Convert category string to enum (simplified)
            VulnCategory category = VulnCategory::RECONNAISSANCE; // Default
            
            BluetoothTarget target;
            target.mac_address = target_mac;
            
            std::cout << "[+] Ejecutando categoría: " << category_name << std::endl;
            std::cout << "[+] Objetivo: " << target_mac << std::endl;
            
            auto results = g_framework->runCategory(category, target);
            
            std::cout << "[+] Ejecutados " << results.size() << " módulos" << std::endl;
            int successful = 0;
            for (const auto& result : results) {
                if (result.success) successful++;
            }
            std::cout << "[+] Exitosos: " << successful << "/" << results.size() << std::endl;
        }
        else {
            std::cout << "\nUso: " << argv[0] << " [opciones]" << std::endl;
            std::cout << "Use --help para ver todas las opciones disponibles." << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "[!] Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
