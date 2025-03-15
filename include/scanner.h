#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>

/**
 * Énumération des états possibles d'un port
 */
typedef enum {
    PORT_OPEN,       // Port ouvert
    PORT_CLOSED,     // Port fermé
    PORT_FILTERED,   // Port filtré (pas de réponse)
    PORT_UNKNOWN     // État indéterminé
} port_state_t;

/**
 * Structure pour stocker les résultats d'un scan de port
 */
typedef struct {
    uint16_t port;           // Numéro du port
    port_state_t state;      // État du port
    char service[32];        // Nom du service associé (si connu)
} port_result_t;

/**
 * Structure pour stocker les résultats d'un scan d'hôte
 */
typedef struct {
    char ip_address[16];             // Adresse IP de l'hôte
    int is_alive;                    // 1 si l'hôte est actif, 0 sinon
    char os_info[64];                // Informations sur le système d'exploitation
    port_result_t *port_results;     // Résultats du scan de ports
    int port_count;                  // Nombre de ports scannés
} host_result_t;

/**
 * Options de configuration pour le scan
 */
typedef struct {
    int start_port;          // Port de début
    int end_port;            // Port de fin
    int timeout_ms;          // Timeout en millisecondes
    int threads;             // Nombre de threads à utiliser
    int scan_type;           // Type de scan (TCP Connect, SYN, UDP)
    int ping_scan;           // 1 pour activer le ping scan, 0 pour le désactiver
    int os_detection;        // 1 pour activer la détection d'OS, 0 pour la désactiver
    int verbose;             // Niveau de verbosité
} scan_options_t;

/**
 * Initialise les options de scan avec des valeurs par défaut
 * 
 * @param options Structure d'options à initialiser
 */
void init_scan_options(scan_options_t *options);

/**
 * Effectue un scan TCP Connect sur un hôte
 * 
 * @param ip_address Adresse IP de l'hôte à scanner
 * @param options Options de configuration du scan
 * @param result Pointeur vers la structure qui recevra les résultats
 * @return 0 en cas de succès, code d'erreur sinon
 */
int tcp_connect_scan(const char *ip_address, scan_options_t *options, host_result_t *result);

/**
 * Effectue un scan SYN sur un hôte (nécessite des privilèges administrateur)
 * 
 * @param ip_address Adresse IP de l'hôte à scanner
 * @param options Options de configuration du scan
 * @param result Pointeur vers la structure qui recevra les résultats
 * @return 0 en cas de succès, code d'erreur sinon
 */
int tcp_syn_scan(const char *ip_address, scan_options_t *options, host_result_t *result);

/**
 * Effectue un scan UDP sur un hôte
 * 
 * @param ip_address Adresse IP de l'hôte à scanner
 * @param options Options de configuration du scan
 * @param result Pointeur vers la structure qui recevra les résultats
 * @return 0 en cas de succès, code d'erreur sinon
 */
int udp_scan(const char *ip_address, scan_options_t *options, host_result_t *result);

/**
 * Vérifie si un hôte est actif en utilisant des paquets ICMP (ping)
 * 
 * @param ip_address Adresse IP de l'hôte à vérifier
 * @param timeout_ms Timeout en millisecondes
 * @return 1 si l'hôte est actif, 0 sinon
 */
int host_discovery(const char *ip_address, int timeout_ms);

/**
 * Tente de détecter le système d'exploitation de l'hôte
 * 
 * @param ip_address Adresse IP de l'hôte
 * @param os_info Buffer pour stocker les informations sur l'OS
 * @param buffer_size Taille du buffer
 * @return 0 en cas de succès, code d'erreur sinon
 */
int os_detection(const char *ip_address, char *os_info, size_t buffer_size);

/**
 * Libère les ressources allouées pour une structure host_result_t
 * 
 * @param result Pointeur vers la structure à libérer
 */
void free_host_result(host_result_t *result);

#endif /* SCANNER_H */
