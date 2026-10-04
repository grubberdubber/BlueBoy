#!/bin/bash
# BlueBoy Framework - Script de Instalación
# Este script instala todas las dependencias y compila el framework

set -e

echo "======================================"
echo "BlueBoy Framework - Instalación"
echo "======================================"

# Verificar si se ejecuta como root para dependencias del sistema
if [[ $EUID -eq 0 ]]; then
    echo "[!] No ejecute este script como root. Use sudo solo cuando se solicite."
    exit 1
fi

# Detectar distribución
if [ -f /etc/debian_version ]; then
    DISTRO="debian"
elif [ -f /etc/redhat-release ]; then
    DISTRO="redhat"
else
    echo "[!] Distribución no soportada. Instale manualmente las dependencias."
    exit 1
fi

echo "[+] Distribución detectada: $DISTRO"

# Instalar dependencias del sistema
echo "[+] Instalando dependencias del sistema..."

if [ "$DISTRO" = "debian" ]; then
    sudo apt-get update
    sudo apt-get install -y \
        build-essential \
        cmake \
        pkg-config \
        libbluetooth-dev \
        bluez \
        bluez-tools \
        libpcap-dev \
        libboost-all-dev \
        libssl-dev \
        libglib2.0-dev \
        git
elif [ "$DISTRO" = "redhat" ]; then
    sudo yum install -y \
        gcc-c++ \
        cmake \
        pkgconfig \
        bluez-libs-devel \
        libpcap-devel \
        boost-devel \
        openssl-devel \
        glib2-devel \
        git
fi

echo "[+] Dependencias instaladas exitosamente"

# Crear directorios necesarios
echo "[+] Creando directorios..."
mkdir -p build output logs config

# Compilar el framework
echo "[+] Compilando BlueBoy Framework..."
cd build
cmake ..
make -j$(nproc)
cd ..

echo "[+] Compilación completada"

# Configurar permisos
echo "[+] Configurando permisos..."
chmod +x build/blueboy

# Verificar instalación
echo "[+] Verificando instalación..."
if [ -f "build/blueboy" ]; then
    echo "[+] ✓ Ejecutable creado exitosamente"
    ./build/blueboy --help > /dev/null 2>&1 && echo "[+] ✓ Framework funcional"
else
    echo "[!] Error: No se pudo crear el ejecutable"
    exit 1
fi

echo ""
echo "======================================"
echo "Instalación Completada!"
echo "======================================"
echo ""
echo "Para usar BlueBoy Framework:"
echo "  ./build/blueboy --help"
echo "  ./build/blueboy --list-modules"
echo "  ./build/blueboy --interactive"
echo ""
echo "Para instalar globalmente:"
echo "  sudo make install"
echo ""
echo "IMPORTANTE: Este framework es solo para fines educativos"
echo "y pruebas autorizadas. Use responsablemente."
