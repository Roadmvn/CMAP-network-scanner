#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <errno.h>

#include "../include/utils.h"
#include "../include/scanner.h"

// Messages d'erreur correspondant aux codes d'erreur
static const char *error_messages[] = {
    "Aucune erreur",
    "Arguments invalides",
    "Erreur lors de la création du socket",
    "Erreur lors de la connexion au socket",
    "Timeout lors de la connexion",
    "Erreur d'allocation mémoire",
    "Permission refusée (privilèges administrateur requis)",
    "Erreur inconnue"
};

// Affiche un message d'erreur correspondant au code d'erreur
void print_error(error_code_t error_code) {
    if (error_code >= 0 && error_code < sizeof(error_messages) / sizeof(error_messages[0])) {
        printf("Erreur : %s\n", error_messages[error_code]);
    } else {
        printf("Erreur inconnue (code %d)\n", error_code);
    }
}

// Vérifie si une adresse IP est valide
int is_valid_ip(const char *ip_address) {
    struct sockaddr_in sa;
    return inet_pton(AF_INET, ip_address, &(sa.sin_addr)) == 1;
}

// Parse les arguments de la ligne de commande
int parse_arguments(int argc, char *argv[], char *ip_address, size_t ip_size, scan_options_t *options) {
    size_t i;
    
    // Vérification du nombre minimal d'arguments
    if (argc < 2) {
        return ERROR_INVALID_ARGS;
    }
    
    // Copie de l'adresse IP
    strncpy(ip_address, argv[1], ip_size - 1);
    ip_address[ip_size - 1] = '\0';
    
    // Initialisation des options avec les valeurs par défaut
    init_scan_options(options);
    
    // Parsing des arguments
    for (i = 2; i < (size_t)argc; i++) {
        // Vérification si l'argument est un port ou une option
        if (argv[i][0] != '-' && i == 2) {
            // Premier argument numérique = port de début
            options->start_port = atoi(argv[i]);
            if (options->start_port <= 0 || options->start_port > 65535) {
                return ERROR_INVALID_ARGS;
            }
        } else if (argv[i][0] != '-' && i == 3) {
            // Deuxième argument numérique = port de fin
            options->end_port = atoi(argv[i]);
            if (options->end_port <= 0 || options->end_port > 65535 || options->end_port < options->start_port) {
                return ERROR_INVALID_ARGS;
            }
        } else if (strcmp(argv[i], "--os-detection") == 0) {
            options->os_detection = 1;
        } else if (strcmp(argv[i], "--udp") == 0) {
            options->scan_type = 3; // UDP scan
        } else if (strcmp(argv[i], "--syn") == 0) {
            options->scan_type = 2; // SYN scan
        } else if (strcmp(argv[i], "--verbose") == 0) {
            options->verbose = 1;
        } else if (strcmp(argv[i], "-Pn") == 0) {
            options->ping_scan = 0;
        } else if (strcmp(argv[i], "--threads") == 0 && i + 1 < (size_t)argc) {
            options->threads = atoi(argv[i + 1]);
            if (options->threads <= 0) {
                options->threads = 1;
            } else if (options->threads > 32) {
                options->threads = 32;
            }
            i++;
        } else if (strcmp(argv[i], "--timeout") == 0 && i + 1 < (size_t)argc) {
            options->timeout_ms = atoi(argv[i + 1]);
            if (options->timeout_ms <= 0) {
                options->timeout_ms = 2000;
            }
            i++;
        } else if (argv[i][0] == '-') {
            // Option inconnue
            return ERROR_INVALID_ARGS;
        }
    }
    
    return ERROR_NONE;
}

// Affiche l'aide du programme
void print_help() {
    printf("Usage: nmap_clone <ip_address> [start_port] [end_port] [options]\n");
    printf("\n");
    printf("Options:\n");
    printf("  --os-detection     Active la détection du système d'exploitation\n");
    printf("  --udp              Effectue un scan UDP au lieu d'un scan TCP Connect\n");
    printf("  --syn              Effectue un scan TCP SYN (nécessite des privilèges administrateur)\n");
    printf("  --verbose          Affiche des informations détaillées\n");
    printf("  -Pn                Désactive la détection d'hôte (ping)\n");
    printf("  --threads <n>      Nombre de threads à utiliser (défaut: 4, max: 32)\n");
    printf("  --timeout <ms>     Timeout en millisecondes (défaut: 2000)\n");
    printf("\n");
    printf("Exemple:\n");
    printf("  nmap_clone 192.168.1.1 1 1024 --os-detection --verbose\n");
}

// Affiche les résultats d'un scan d'hôte
void print_scan_results(const host_result_t *result, int verbose) {
    int open_count = 0, closed_count = 0, filtered_count = 0;
    int has_open_ports = 0;
    
    printf("Résultats pour l'hôte : %s\n\n", result->ip_address);
    
    if (result->os_info[0] != '\0') {
        printf("OS probable : %s\n\n", result->os_info);
    }
    
    printf("PORT\t\tÉTAT\t\tSERVICE\n");
    printf("----\t\t----\t\t-------\n");
    
    // Premier passage pour compter les ports par état
    for (size_t i = 0; i < (size_t)result->port_count; i++) {
        const port_result_t *port = &result->port_results[i];
        
        // Comptage des ports par état
        switch (port->state) {
            case PORT_OPEN:
                open_count++;
                has_open_ports = 1;
                break;
            case PORT_CLOSED:
                closed_count++;
                break;
            case PORT_FILTERED:
                filtered_count++;
                break;
            default:
                break;
        }
    }
    
    // Affichage des ports selon le niveau de verbosité
    if (has_open_ports || verbose) {
        for (size_t i = 0; i < (size_t)result->port_count; i++) {
            const port_result_t *port = &result->port_results[i];
            
            if (verbose || port->state == PORT_OPEN) {
                if (strcmp(port->service, "inconnu") != 0) {
                    printf("%d\t\t%s\t\t%s\n", 
                           port->port, 
                           port_state_to_string(port->state),
                           port->service);
                }
            }
        }
    } else {
        printf("Aucun port ouvert détecté\n");
    }
    
    printf("\n");
    printf("Statistiques: %d ports scannés, %d ouverts, %d fermés, %d filtrés\n",
           result->port_count, open_count, closed_count, filtered_count);
}

// Obtient le nom du service associé à un port
void get_service_name(uint16_t port, const char *protocol, char *service, size_t service_size) {
    // Liste simplifiée des services courants
    struct {
        uint16_t port;
        const char *protocol;
        const char *name;
    } known_services[] = {
        { 21, "tcp", "FTP" },
        { 22, "tcp", "SSH" },
        { 23, "tcp", "Telnet" },
        { 25, "tcp", "SMTP" },
        { 53, "tcp", "DNS" },
        { 53, "udp", "DNS" },
        { 80, "tcp", "HTTP" },
        { 110, "tcp", "POP3" },
        { 111, "tcp", "RPC" },
        { 111, "udp", "RPC" },
        { 135, "tcp", "MSRPC" },
        { 139, "tcp", "NetBIOS" },
        { 143, "tcp", "IMAP" },
        { 161, "udp", "SNMP" },
        { 443, "tcp", "HTTPS" },
        { 445, "tcp", "SMB" },
        { 993, "tcp", "IMAPS" },
        { 995, "tcp", "POP3S" },
        { 1723, "tcp", "PPTP" },
        { 3306, "tcp", "MySQL" },
        { 3389, "tcp", "RDP" },
        { 5900, "tcp", "VNC" },
        { 8080, "tcp", "HTTP-Proxy" }
    };
    
    size_t i;
    size_t num_services = sizeof(known_services) / sizeof(known_services[0]);
    
    for (i = 0; i < num_services; i++) {
        if (known_services[i].port == port && strcmp(known_services[i].protocol, protocol) == 0) {
            strncpy(service, known_services[i].name, service_size - 1);
            service[service_size - 1] = '\0';
            return;
        }
    }
    
    // Service inconnu
    strncpy(service, "inconnu", service_size - 1);
    service[service_size - 1] = '\0';
}

// Convertit un état de port en chaîne de caractères
const char *port_state_to_string(port_state_t state) {
    switch (state) {
        case PORT_OPEN:
            return "ouvert";
        case PORT_CLOSED:
            return "fermé";
        case PORT_FILTERED:
            return "filtré";
        case PORT_UNKNOWN:
        default:
            return "inconnu";
    }
}

// Obtient le temps actuel en millisecondes
unsigned long get_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

// Crée une plage d'adresses IP à partir d'une notation CIDR
int generate_ip_range(const char *cidr, char **ip_list, int max_ips) {
    char ip_part[16];
    int prefix_len;
    uint32_t ip_binary, netmask, network, broadcast, current_ip;
    int count = 0;
    struct in_addr addr;
    
    // Extraction de l'adresse IP et de la longueur du préfixe
    if (sscanf(cidr, "%15[^/]/%d", ip_part, &prefix_len) != 2) {
        return 0;
    }
    
    // Vérification de la validité de l'adresse IP
    if (!is_valid_ip(ip_part)) {
        return 0;
    }
    
    // Vérification de la validité de la longueur du préfixe
    if (prefix_len < 0 || prefix_len > 32) {
        return 0;
    }
    
    // Conversion de l'adresse IP en format binaire
    inet_pton(AF_INET, ip_part, &ip_binary);
    ip_binary = ntohl(ip_binary);
    
    // Calcul du masque réseau
    netmask = prefix_len == 0 ? 0 : ~((1 << (32 - prefix_len)) - 1);
    
    // Calcul de l'adresse réseau et de broadcast
    network = ip_binary & netmask;
    broadcast = network | ~netmask;
    
    // Génération des adresses IP
    for (current_ip = network + 1; current_ip < broadcast && count < max_ips; current_ip++) {
        addr.s_addr = htonl(current_ip);
        inet_ntop(AF_INET, &addr, ip_list[count], 16);
        count++;
    }
    
    return count;
}
