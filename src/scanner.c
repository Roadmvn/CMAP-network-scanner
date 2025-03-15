#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/time.h>

#include "../include/scanner.h"
#include "../include/utils.h"
#include "../include/network.h"

// Structure pour les arguments des threads
typedef struct {
    const char *ip_address;
    int start_port;
    int end_port;
    int timeout_ms;
    port_result_t *results;
    int *completed;
} thread_args_t;

// Fonction pour initialiser les options de scan avec des valeurs par défaut
void init_scan_options(scan_options_t *options) {
    if (options == NULL) {
        return;
    }
    
    options->start_port = 1;
    options->end_port = 1024;
    options->timeout_ms = 2000;
    options->threads = 4;
    options->scan_type = 1; // TCP Connect par défaut
    options->ping_scan = 1; // Ping activé par défaut
    options->os_detection = 0; // Détection d'OS désactivée par défaut
    options->verbose = 0; // Verbosité minimale par défaut
}

// Déclaration des fonctions statiques
static port_state_t scan_tcp_port_connect(const char *ip_address, int port, int timeout_ms);
static void *tcp_connect_scan_thread(void *arg);
static port_state_t scan_udp_port(const char *ip_address, int port, int timeout_ms);
static void *udp_scan_thread(void *arg);
static int try_tcp_connection(const char *ip_address, int port, int timeout_ms);

// Fonction spécifique pour scanner localhost
static port_state_t scan_localhost_port(int port, int timeout_ms) {
    int sock;
    struct sockaddr_in addr;
    int result;
    struct timeval tv;
    
    // Création du socket
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return PORT_UNKNOWN;
    }
    
    // Configuration du timeout
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv);
    
    // Configuration de l'adresse
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    
    // Tentative de connexion
    result = connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    // Fermeture du socket
    close(sock);
    
    if (result == 0) {
        return PORT_OPEN;
    } else {
        if (errno == ETIMEDOUT || errno == EHOSTUNREACH) {
            return PORT_FILTERED;
        } else {
            return PORT_CLOSED;
        }
    }
}

// Fonction pour scanner un port TCP avec la méthode connect()
static port_state_t scan_tcp_port_connect(const char *ip_address, int port, int timeout_ms) {
    // Traitement spécial pour localhost
    if (strcmp(ip_address, "127.0.0.1") == 0 || strcmp(ip_address, "localhost") == 0) {
        return scan_localhost_port(port, timeout_ms);
    }
    
    int sock;
    struct sockaddr_in server;
    int result;
    fd_set fdset;
    struct timeval tv;
    int so_error;
    socklen_t len = sizeof(so_error);
    
    // Création du socket
    sock = create_tcp_socket();
    if (sock == INVALID_SOCKET) {
        return PORT_UNKNOWN;
    }
    
    // Passage du socket en mode non-bloquant
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    // Configuration de l'adresse du serveur
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip_address, &server.sin_addr);
    
    // Tentative de connexion
    result = connect(sock, (struct sockaddr *)&server, sizeof(server));
    
    // Vérification du résultat immédiat
    if (result == 0) {
        // Connexion immédiate (rare)
        close(sock);
        return PORT_OPEN;
    }
    
    // Si errno n'est pas EINPROGRESS, la connexion a échoué immédiatement
    if (errno != EINPROGRESS) {
        close(sock);
        return PORT_CLOSED;
    }
    
    // Attente de la connexion avec select()
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    result = select(sock + 1, NULL, &fdset, NULL, &tv);
    
    if (result == 0) {
        // Timeout, la connexion n'a pas abouti
        close(sock);
        return PORT_FILTERED;
    }
    
    // Vérification de l'état de la connexion
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    
    // Fermeture du socket
    close(sock);
    
    if (so_error == 0) {
        return PORT_OPEN;
    } else if (so_error == ETIMEDOUT || so_error == EHOSTUNREACH || so_error == ECONNREFUSED) {
        if (so_error == ECONNREFUSED) {
            return PORT_CLOSED;
        } else {
            return PORT_FILTERED;
        }
    }
    
    return PORT_CLOSED;
}

// Fonction thread pour le scan TCP Connect
static void *tcp_connect_scan_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    int i, index;
    
    for (i = args->start_port; i <= args->end_port; i++) {
        index = i - args->start_port;
        args->results[index].port = i;
        args->results[index].state = scan_tcp_port_connect(args->ip_address, i, args->timeout_ms);
        
        // Récupération du nom du service
        get_service_name(i, "tcp", args->results[index].service, sizeof(args->results[index].service));
    }
    
    (*args->completed)++;
    free(args);
    return NULL;
}

// Fonction pour effectuer un scan TCP Connect
int tcp_connect_scan(const char *ip_address, scan_options_t *options, host_result_t *result) {
    int num_ports = options->end_port - options->start_port + 1;
    int ports_per_thread, remaining_ports;
    int i, thread_count = 0;
    int completed_threads = 0;
    pthread_t *threads;
    thread_args_t *args;
    
    // Allocation de la mémoire pour les résultats
    result->port_results = (port_result_t *)malloc(num_ports * sizeof(port_result_t));
    if (result->port_results == NULL) {
        return ERROR_MEMORY_ALLOCATION;
    }
    result->port_count = num_ports;
    
    // Détermination du nombre de threads à utiliser
    int num_threads = options->threads;
    if (num_threads > num_ports) {
        num_threads = num_ports;
    }
    
    // Allocation de la mémoire pour les handles de threads
    threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    if (threads == NULL) {
        free(result->port_results);
        result->port_results = NULL;
        return ERROR_MEMORY_ALLOCATION;
    }
    
    // Calcul du nombre de ports par thread
    ports_per_thread = num_ports / num_threads;
    remaining_ports = num_ports % num_threads;
    
    // Création des threads
    int start_port = options->start_port;
    for (i = 0; i < num_threads; i++) {
        int thread_ports = ports_per_thread + (i < remaining_ports ? 1 : 0);
        int end_port = start_port + thread_ports - 1;
        
        args = (thread_args_t *)malloc(sizeof(thread_args_t));
        if (args == NULL) {
            continue;
        }
        
        args->ip_address = ip_address;
        args->start_port = start_port;
        args->end_port = end_port;
        args->timeout_ms = options->timeout_ms;
        args->results = &result->port_results[start_port - options->start_port];
        args->completed = &completed_threads;
        
        if (pthread_create(&threads[thread_count], NULL, tcp_connect_scan_thread, args) == 0) {
            thread_count++;
        } else {
            free(args);
        }
        
        start_port = end_port + 1;
    }
    
    // Attente de la fin de tous les threads
    for (i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    
    return ERROR_NONE;
}

// Fonction pour effectuer un scan SYN (nécessite des privilèges administrateur)
int tcp_syn_scan(const char *ip_address, scan_options_t *options, host_result_t *result) {
    // Vérification des privilèges administrateur
    if (geteuid() != 0) {
        printf("Le scan SYN nécessite des privilèges administrateur\n");
        return ERROR_PERMISSION_DENIED;
    }
    
    // Implémentation simplifiée du scan SYN
    // Dans une implémentation complète, il faudrait créer des paquets TCP SYN bruts
    // et analyser les réponses SYN-ACK, RST, etc.
    
    // Pour l'instant, on utilise le scan TCP Connect comme fallback
    printf("Scan SYN non implémenté complètement, utilisation du scan TCP Connect comme fallback\n");
    return tcp_connect_scan(ip_address, options, result);
}

// Fonction pour scanner un port UDP
static port_state_t scan_udp_port(const char *ip_address, int port, int timeout_ms) {
    int sock;
    struct sockaddr_in server;
    char buffer[1] = {0};
    int result;
    
    // Création du socket UDP
    sock = create_udp_socket();
    if (sock == INVALID_SOCKET) {
        return PORT_UNKNOWN;
    }
    
    // Configuration du timeout
    set_socket_timeout(sock, timeout_ms);
    
    // Configuration de l'adresse du serveur
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip_address, &server.sin_addr);
    
    // Envoi d'un paquet UDP vide
    result = sendto(sock, buffer, 1, 0, (struct sockaddr *)&server, sizeof(server));
    if (result == SOCKET_ERROR) {
        close(sock);
        return PORT_UNKNOWN;
    }
    
    // Tentative de réception d'une réponse
    fd_set readfds;
    struct timeval tv;
    
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    result = select(sock + 1, &readfds, NULL, NULL, &tv);
    
    // Fermeture du socket
    close(sock);
    
    // Analyse du résultat
    if (result == 0) {
        // Timeout, pas de réponse
        return PORT_OPEN;  // En UDP, pas de réponse peut signifier ouvert ou filtré
    } else if (result == SOCKET_ERROR) {
        return PORT_UNKNOWN;
    } else {
        // Réception d'une réponse ICMP Port Unreachable
        return PORT_CLOSED;
    }
}

// Fonction thread pour le scan UDP
static void *udp_scan_thread(void *arg) {
    thread_args_t *args = (thread_args_t *)arg;
    int i, index;
    
    for (i = args->start_port; i <= args->end_port; i++) {
        index = i - args->start_port;
        args->results[index].port = i;
        args->results[index].state = scan_udp_port(args->ip_address, i, args->timeout_ms);
        
        // Récupération du nom du service
        get_service_name(i, "udp", args->results[index].service, sizeof(args->results[index].service));
    }
    
    (*args->completed)++;
    free(args);
    return NULL;
}

// Fonction pour effectuer un scan UDP
int udp_scan(const char *ip_address, scan_options_t *options, host_result_t *result) {
    int num_ports = options->end_port - options->start_port + 1;
    int ports_per_thread, remaining_ports;
    int i, thread_count = 0;
    int completed_threads = 0;
    pthread_t *threads;
    thread_args_t *args;
    
    // Allocation de la mémoire pour les résultats
    result->port_results = (port_result_t *)malloc(num_ports * sizeof(port_result_t));
    if (result->port_results == NULL) {
        return ERROR_MEMORY_ALLOCATION;
    }
    result->port_count = num_ports;
    
    // Détermination du nombre de threads à utiliser
    int num_threads = options->threads;
    if (num_threads > num_ports) {
        num_threads = num_ports;
    }
    
    // Allocation de la mémoire pour les handles de threads
    threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    if (threads == NULL) {
        free(result->port_results);
        result->port_results = NULL;
        return ERROR_MEMORY_ALLOCATION;
    }
    
    // Calcul du nombre de ports par thread
    ports_per_thread = num_ports / num_threads;
    remaining_ports = num_ports % num_threads;
    
    // Création des threads
    int start_port = options->start_port;
    for (i = 0; i < num_threads; i++) {
        int thread_ports = ports_per_thread + (i < remaining_ports ? 1 : 0);
        int end_port = start_port + thread_ports - 1;
        
        args = (thread_args_t *)malloc(sizeof(thread_args_t));
        if (args == NULL) {
            continue;
        }
        
        args->ip_address = ip_address;
        args->start_port = start_port;
        args->end_port = end_port;
        args->timeout_ms = options->timeout_ms;
        args->results = &result->port_results[start_port - options->start_port];
        args->completed = &completed_threads;
        
        if (pthread_create(&threads[thread_count], NULL, udp_scan_thread, args) == 0) {
            thread_count++;
        } else {
            free(args);
        }
        
        start_port = end_port + 1;
    }
    
    // Attente de la fin de tous les threads
    for (i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    
    return ERROR_NONE;
}

// Fonction pour vérifier si un hôte est actif en utilisant ICMP (ping)
int host_discovery(const char *ip_address, int timeout_ms) {
    // Si l'adresse est localhost, on considère qu'elle est toujours active
    if (strcmp(ip_address, "127.0.0.1") == 0 || strcmp(ip_address, "localhost") == 0) {
        return 1;
    }

    int sock;
    icmp_packet_t packet;
    int result;
    
    // Création d'un socket RAW pour ICMP
    sock = create_raw_socket();
    if (sock == INVALID_SOCKET) {
        // Si on ne peut pas créer de socket raw (permissions), on tente une connexion TCP sur le port 80
        return try_tcp_connection(ip_address, 80, timeout_ms);
    }
    
    // Configuration du timeout
    set_socket_timeout(sock, timeout_ms);
    
    // Préparation du paquet ICMP Echo Request
    memset(&packet, 0, sizeof(packet));
    packet.type = 8;  // Echo Request
    packet.code = 0;
    packet.id = (uint16_t)getpid();
    packet.sequence = 1;
    
    // Remplissage des données avec un timestamp
    memcpy(packet.data, &timeout_ms, sizeof(timeout_ms));
    
    // Calcul de la somme de contrôle
    packet.checksum = 0;
    packet.checksum = calculate_checksum((uint16_t *)&packet, sizeof(packet));
    
    // Envoi du paquet ICMP
    result = send_icmp_echo(sock, ip_address, &packet);
    if (result != 0) {
        close(sock);
        // Si l'envoi échoue, on tente une connexion TCP sur le port 80
        return try_tcp_connection(ip_address, 80, timeout_ms);
    }
    
    // Réception de la réponse
    result = receive_icmp_reply(sock, &packet, timeout_ms);
    
    // Fermeture du socket
    close(sock);
    
    if (result != 0) {
        // Si la réception échoue, on tente une connexion TCP sur le port 80
        return try_tcp_connection(ip_address, 80, timeout_ms);
    }
    
    return 1;
}

// Fonction pour tenter une connexion TCP comme méthode alternative de détection d'hôte
static int try_tcp_connection(const char *ip_address, int port, int timeout_ms) {
    int sock;
    struct sockaddr_in server;
    int result;
    
    // Création du socket
    sock = create_tcp_socket();
    if (sock == INVALID_SOCKET) {
        return 0;
    }
    
    // Configuration du timeout
    set_socket_timeout(sock, timeout_ms);
    
    // Configuration de l'adresse du serveur
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip_address, &server.sin_addr);
    
    // Tentative de connexion
    result = connect(sock, (struct sockaddr *)&server, sizeof(server));
    
    // Fermeture du socket
    close(sock);
    
    return (result == 0);
}

// Fonction pour tenter de détecter le système d'exploitation de l'hôte
int os_detection(const char *ip_address, char *os_info, size_t buffer_size) {
    // Cette fonction est une version simplifiée de la détection d'OS
    // Une implémentation complète nécessiterait une analyse fine des réponses TCP/IP
    
    // Pour l'instant, on utilise une approche basique basée sur les ports ouverts
    scan_options_t options;
    host_result_t result = {0};
    int has_windows_ports = 0;
    int has_linux_ports = 0;
    int i;
    
    init_scan_options(&options);
    options.start_port = 1;
    options.end_port = 1024;
    options.timeout_ms = 1000;
    options.threads = 4;
    
    // Scan TCP pour détecter les ports ouverts
    if (tcp_connect_scan(ip_address, &options, &result) != ERROR_NONE) {
        strncpy(os_info, "Inconnu", buffer_size - 1);
        return ERROR_UNKNOWN;
    }
    
    // Analyse des ports ouverts pour deviner l'OS
    for (i = 0; i < result.port_count; i++) {
        if (result.port_results[i].state == PORT_OPEN) {
            int port = result.port_results[i].port;
            
            // Ports typiquement ouverts sur Windows
            if (port == 135 || port == 139 || port == 445 || port == 3389) {
                has_windows_ports++;
            }
            
            // Ports typiquement ouverts sur Linux
            if (port == 22 || port == 111 || port == 2049) {
                has_linux_ports++;
            }
        }
    }
    
    // Libération des ressources
    free_host_result(&result);
    
    // Détermination de l'OS probable
    if (has_windows_ports > has_linux_ports) {
        strncpy(os_info, "Windows (probable)", buffer_size - 1);
    } else if (has_linux_ports > has_windows_ports) {
        strncpy(os_info, "Linux/Unix (probable)", buffer_size - 1);
    } else {
        strncpy(os_info, "Indéterminé", buffer_size - 1);
    }
    
    return ERROR_NONE;
}

// Fonction pour libérer les ressources allouées pour une structure host_result_t
void free_host_result(host_result_t *result) {
    if (result == NULL) {
        return;
    }
    
    if (result->port_results != NULL) {
        free(result->port_results);
        result->port_results = NULL;
    }
    
    result->port_count = 0;
}
