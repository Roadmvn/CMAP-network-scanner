#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>

#define TEST_PORT 8888

int server_socket = -1;

// Fonction pour gérer les signaux d'interruption
void signal_handler(int sig) {
    printf("\nInterruption détectée. Arrêt du serveur de test...\n");
    if (server_socket != -1) {
        close(server_socket);
    }
    exit(EXIT_SUCCESS);
}

int main() {
    struct sockaddr_in server_addr;
    int opt = 1;
    
    // Configuration du gestionnaire de signaux
    signal(SIGINT, signal_handler);
    
    // Création du socket
    if ((server_socket = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("Erreur lors de la création du socket");
        return EXIT_FAILURE;
    }
    
    // Configuration des options du socket
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) == -1) {
        perror("Erreur lors de la configuration du socket");
        close(server_socket);
        return EXIT_FAILURE;
    }
    
    // Configuration de l'adresse du serveur
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(TEST_PORT);
    
    // Liaison du socket à l'adresse
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("Erreur lors de la liaison du socket");
        close(server_socket);
        return EXIT_FAILURE;
    }
    
    // Mise en écoute du socket
    if (listen(server_socket, 5) == -1) {
        perror("Erreur lors de la mise en écoute du socket");
        close(server_socket);
        return EXIT_FAILURE;
    }
    
    printf("Serveur de test démarré sur le port %d\n", TEST_PORT);
    printf("Appuyez sur Ctrl+C pour arrêter le serveur\n");
    
    // Boucle principale pour accepter les connexions
    while (1) {
        int client_socket;
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == -1) {
            perror("Erreur lors de l'acceptation de la connexion");
            continue;
        }
        
        char client_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));
        printf("Connexion reçue de %s:%d\n", client_ip, ntohs(client_addr.sin_port));
        
        // Envoi d'un message de bienvenue
        const char *message = "Bienvenue sur le serveur de test CMAP!\n";
        send(client_socket, message, strlen(message), 0);
        
        // Fermeture de la connexion
        close(client_socket);
    }
    
    return EXIT_SUCCESS;
}
