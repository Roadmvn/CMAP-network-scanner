#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>

#include "../include/scanner.h"
#include "../include/utils.h"
#include "../include/network.h"

// Fonction pour afficher la bannière du programme
void print_banner() {
    printf(" ██████╗ ███╗   ███╗ █████╗ ██████╗ \n");
    printf("██╔════╝ ████╗ ████║██╔══██╗██╔══██╗\n");
    printf("██║      ██╔████╔██║███████║██████╔╝\n");
    printf("██║      ██║╚██╔╝██║██╔══██║██╔═══╝ \n");
    printf("╚██████╗ ██║ ╚═╝ ██║██║  ██║██║     \n");
    printf(" ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     \n");
    printf("\n");
    printf("=======================================================\n");
    printf("  Outil de scan réseau (Clone de Nmap en C)           \n");
    printf("=======================================================\n");
    printf("\n");
}

// Fonction pour gérer les signaux d'interruption
void signal_handler(int sig) {
    (void)sig; // Évite l'avertissement de paramètre non utilisé
    printf("\nInterruption détectée. Arrêt du programme...\n");
    exit(EXIT_SUCCESS);
}

int main(int argc, char *argv[]) {
    char ip_address[16] = {0};
    scan_options_t options;
    host_result_t result = {0};
    error_code_t error;
    unsigned long start_time, end_time;

    // Configuration du gestionnaire de signaux
    signal(SIGINT, signal_handler);
    
    // Affichage de la bannière
    print_banner();
    
    // Initialisation des options de scan
    init_scan_options(&options);

    // Analyse des arguments de la ligne de commande
    if (argc < 2) {
        print_help();
        return EXIT_SUCCESS;
    }
    
    // Vérification si l'utilisateur demande l'aide
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help();
        return EXIT_SUCCESS;
    }

    // Parsing des arguments
    error = parse_arguments(argc, argv, ip_address, sizeof(ip_address), &options);
    if (error != ERROR_NONE) {
        print_error(error);
        return EXIT_FAILURE;
    }

    // Vérification de la validité de l'adresse IP
    if (!is_valid_ip(ip_address)) {
        printf("Erreur : Adresse IP invalide '%s'\n", ip_address);
        return EXIT_FAILURE;
    }

    // Initialisation de la bibliothèque réseau
    if (init_network() != 0) {
        printf("Erreur : Impossible d'initialiser la bibliothèque réseau\n");
        return EXIT_FAILURE;
    }

    // Enregistrement du temps de début
    start_time = get_time_ms();

    printf("Scan de l'hôte %s (ports %d-%d)...\n\n", ip_address, options.start_port, options.end_port);

    // Copie de l'adresse IP dans la structure de résultat
    strncpy(result.ip_address, ip_address, sizeof(result.ip_address) - 1);
    result.ip_address[sizeof(result.ip_address) - 1] = '\0';

    // Vérification si l'hôte est actif (sauf si -Pn est spécifié)
    if (options.ping_scan) {
        printf("Vérification si l'hôte est actif...\n");
        if (!host_discovery(ip_address, options.timeout_ms)) {
            printf("L'hôte %s semble inactif. Utilisez l'option -Pn pour forcer le scan.\n", ip_address);
            return EXIT_FAILURE;
        }
        printf("L'hôte %s est actif.\n\n", ip_address);
    }

    // Détection du système d'exploitation si demandé
    if (options.os_detection) {
        printf("Détection du système d'exploitation...\n");
        os_detection(ip_address, result.os_info, sizeof(result.os_info));
    }

    // Scan des ports selon le type de scan demandé
    switch (options.scan_type) {
        case 1: // TCP Connect
            printf("Scan TCP Connect en cours...\n");
            error = tcp_connect_scan(ip_address, &options, &result);
            break;
        case 2: // TCP SYN
            printf("Scan TCP SYN en cours...\n");
            error = tcp_syn_scan(ip_address, &options, &result);
            break;
        case 3: // UDP
            printf("Scan UDP en cours...\n");
            error = udp_scan(ip_address, &options, &result);
            break;
        default:
            error = ERROR_INVALID_ARGS;
            break;
    }

    if (error != ERROR_NONE) {
        print_error(error);
        free_host_result(&result);
        return EXIT_FAILURE;
    }

    // Enregistrement du temps de fin
    end_time = get_time_ms();

    // Affichage des résultats
    printf("\nScan terminé en %.2f secondes.\n\n", (end_time - start_time) / 1000.0);
    print_scan_results(&result, options.verbose);

    // Libération des ressources
    free_host_result(&result);

    return EXIT_SUCCESS;
}
