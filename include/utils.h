#ifndef UTILS_H
#define UTILS_H

#include "scanner.h"

/**
 * Codes d'erreur utilisés dans l'application
 */
typedef enum {
    ERROR_NONE = 0,
    ERROR_INVALID_ARGS,
    ERROR_SOCKET_CREATION,
    ERROR_SOCKET_CONNECT,
    ERROR_SOCKET_TIMEOUT,
    ERROR_MEMORY_ALLOCATION,
    ERROR_PERMISSION_DENIED,
    ERROR_UNKNOWN
} error_code_t;

/**
 * Affiche un message d'erreur correspondant au code d'erreur
 * 
 * @param error_code Code d'erreur
 */
void print_error(error_code_t error_code);

/**
 * Vérifie si une adresse IP est valide
 * 
 * @param ip_address Adresse IP à vérifier
 * @return 1 si l'adresse est valide, 0 sinon
 */
int is_valid_ip(const char *ip_address);

/**
 * Parse les arguments de la ligne de commande
 * 
 * @param argc Nombre d'arguments
 * @param argv Tableau d'arguments
 * @param ip_address Buffer pour stocker l'adresse IP
 * @param ip_size Taille du buffer ip_address
 * @param options Structure pour stocker les options de scan
 * @return 0 en cas de succès, code d'erreur sinon
 */
int parse_arguments(int argc, char *argv[], char *ip_address, size_t ip_size, scan_options_t *options);

/**
 * Affiche l'aide du programme
 */
void print_help();

/**
 * Affiche les résultats d'un scan d'hôte
 * 
 * @param result Résultats du scan
 * @param verbose Niveau de verbosité
 */
void print_scan_results(const host_result_t *result, int verbose);

/**
 * Obtient le nom du service associé à un port
 * 
 * @param port Numéro du port
 * @param protocol Protocole (TCP ou UDP)
 * @param service Buffer pour stocker le nom du service
 * @param service_size Taille du buffer service
 */
void get_service_name(uint16_t port, const char *protocol, char *service, size_t service_size);

/**
 * Convertit un état de port en chaîne de caractères
 * 
 * @param state État du port
 * @return Chaîne de caractères correspondant à l'état
 */
const char *port_state_to_string(port_state_t state);

/**
 * Obtient le temps actuel en millisecondes
 * 
 * @return Temps actuel en millisecondes
 */
unsigned long get_time_ms();

/**
 * Crée une plage d'adresses IP à partir d'une notation CIDR
 * 
 * @param cidr Notation CIDR (ex: 192.168.1.0/24)
 * @param ip_list Tableau pour stocker les adresses IP
 * @param max_ips Taille maximale du tableau
 * @return Nombre d'adresses IP générées
 */
int generate_ip_range(const char *cidr, char **ip_list, int max_ips);

#endif /* UTILS_H */
