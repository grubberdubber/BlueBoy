# BlueBoy - Framework de Vulnerabilidades Bluetooth en C++

Un framework completo para probar y demostrar vulnerabilidades Bluetooth en entornos controlados.

## Descripción General

BlueBoy es un framework modular diseñado en C++ para investigadores de seguridad, pentesters y profesionales de ciberseguridad para entender, probar y demostrar diversas vulnerabilidades Bluetooth de manera ética y controlada.

## Características

- **180+ Módulos de Vulnerabilidades**: Colección completa de vectores de ataque Bluetooth
- **Arquitectura Modular**: Fácil de extender y personalizar
- **Ataques Categorizados**: Organizados por tipo de ataque y severidad
- **Enfoque Educativo**: Documentación detallada y ejemplos
- **Entorno Controlado**: Diseñado solo para pruebas éticas

## Estructura del Framework

```
BlueBoy/
├── src/                     # Código fuente principal
│   ├── core/               # Componentes centrales del framework
│   ├── modules/            # Módulos de vulnerabilidades por categoría
│   │   ├── reconnaissance/ # Ataques de reconocimiento
│   │   ├── exploitation/   # Módulos de explotación activa
│   │   ├── dos/           # Ataques DoS y disrupción
│   │   ├── mitm/          # MITM e intercepción
│   │   ├── privesc/       # Escalación de privilegios
│   │   └── persistence/   # Backdoors y persistencia
│   ├── utils/             # Utilidades y herramientas de soporte
│   └── payloads/          # Payloads y scripts de ataque
├── include/               # Headers del framework
├── lib/                   # Librerías externas
├── build/                 # Archivos de compilación
├── docs/                  # Documentación y guías
├── examples/              # Ejemplos de uso y demos
├── tests/                 # Scripts de testing y validación
├── CMakeLists.txt         # Configuración de CMake
└── Makefile              # Makefile alternativo
```

## Compilación e Instalación

### Requisitos
- C++17 o superior
- CMake 3.15+
- BlueZ development libraries
- libpcap-dev
- boost libraries

### Compilación
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

### Instalación
```bash
sudo make install
```

## Uso Rápido

1. **Listar módulos disponibles**
   ```bash
   ./blueboy --list-modules
   ```

2. **Ejecutar un módulo específico**
   ```bash
   ./blueboy --module BlueBorne --target 00:11:22:33:44:55
   ```

3. **Modo interactivo**
   ```bash
   ./blueboy --interactive
   ```

## Categorías de Vulnerabilidades

### Reconocimiento (30+ módulos)
- Descubrimiento y enumeración de dispositivos
- Identificación de servicios
- Análisis de perfiles

### Explotación (50+ módulos)
- Ejecución remota de código
- Bypass de autenticación
- Explotación de protocolos

### Denegación de Servicio (40+ módulos)
- Flooding de conexiones
- Agotamiento de recursos
- Disrupción de protocolos

### Man-in-the-Middle (25+ módulos)
- Intercepción de tráfico
- Secuestro de sesiones
- Manipulación de protocolos

### Escalación de Privilegios (20+ módulos)
- Escalación local de privilegios
- Explotación de servicios
- Abuso de configuración

### Persistencia (15+ módulos)
- Instalación de backdoors
- Manipulación de servicios
- Persistencia de configuración

## Aviso Legal

⚠️ **IMPORTANTE**: Este framework está destinado únicamente para fines educativos y pruebas de seguridad autorizadas. Los usuarios son responsables de asegurar que tienen la autorización adecuada antes de probar contra cualquier dispositivo o red.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT - ver el archivo LICENSE para detalles.
