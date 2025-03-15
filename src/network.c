#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>

#include "../include/network.h"
#include "../include/utils.h"

// Initialise la bibliothèque réseau
int init_network() {
    // Sous Linux, pas besoin d'initialisation spécifique
    return 0;
}

// Nettoie les ressources réseau
void cleanup_network() {
    // Sous Linux, pas besoin de nettoyage spécifique
}

// Crée un socket TCP
int create_tcp_socket() {
    return socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
}

// Crée un socket UDP
int create_udp_socket() {
    return socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
}

// Crée un socket RAW pour les paquets ICMP
int create_raw_socket() {
    return socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
}

// Configure le timeout d'un socket
int set_socket_timeout(int sock, int timeout_ms) {
    struct timeval tv;
    
    if (sock == -1) {
        return -1;
    }
    
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    // Configuration du timeout pour la réception
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        return -1;
    }
    
    // Configuration du timeout pour l'envoi
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) != 0) {
        return -1;
    }
    
    return 0;
}

// Envoie un paquet ICMP Echo Request (ping)
int send_icmp_echo(int sock, const char *dest_ip, icmp_packet_t *packet) {
    struct sockaddr_in dest;
    int result;
    
    if (sock == -1 || dest_ip == NULL || packet == NULL) {
        return -1;
    }
    
    // Configuration de l'adresse de destination
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    inet_pton(AF_INET, dest_ip, &dest.sin_addr);
    
    // Envoi du paquet ICMP
    result = sendto(sock, (char *)packet, sizeof(icmp_packet_t), 0, (struct sockaddr *)&dest, sizeof(dest));
    
    return (result == -1) ? -1 : 0;
}

// Reçoit une réponse ICMP
int receive_icmp_reply(int sock, icmp_packet_t *packet, int timeout_ms) {
    char buffer[1024];
    struct sockaddr_in sender;
    socklen_t sender_len = sizeof(sender);
    int result;
    fd_set readfds;
    struct timeval tv;
    
    // Configuration du timeout
    FD_ZERO(&readfds);
    FD_SET(sock, &readfds);
    
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    // Attente d'une réponse
    result = select(sock + 1, &readfds, NULL, NULL, &tv);
    if (result <= 0) {
        return -1; // Timeout ou erreur
    }
    
    // Réception du paquet
    result = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&sender, &sender_len);
    if (result <= 0) {
        return -1;
    }
    
    // Vérification de la taille du paquet
    if ((size_t)result >= 20 + sizeof(icmp_packet_t)) {
        // Extraction de l'en-tête ICMP (après l'en-tête IP)
        memcpy(packet, buffer + 20, sizeof(icmp_packet_t));
        return 0;
    }
    
    return -1;
}

// Envoie un paquet TCP SYN
int send_tcp_syn(int sock, const char *dest_ip, uint16_t dest_port, tcp_packet_t *packet) {
    // Éviter les avertissements de paramètres non utilisés
    (void)sock;
    (void)dest_ip;
    (void)dest_port;
    (void)packet;
    
    // Cette fonction nécessite des privilèges administrateur et une implémentation plus complexe
    // Pour une implémentation complète, il faudrait créer des paquets TCP SYN bruts
    return -1; // Non implémenté
}

// Reçoit un paquet TCP
int receive_tcp_packet(int sock, tcp_packet_t *packet, int timeout_ms) {
    // Éviter les avertissements de paramètres non utilisés
    (void)sock;
    (void)packet;
    (void)timeout_ms;
    
    // Cette fonction nécessite une implémentation plus complexe
    return -1; // Non implémenté
}

// Calcule la somme de contrôle pour un paquet IP
uint16_t calculate_checksum(uint16_t *buffer, int size) {
    unsigned long sum = 0;
    
    // Somme de tous les mots de 16 bits
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    
    // S'il reste un octet, on l'ajoute
    if (size == 1) {
        sum += *(unsigned char *)buffer;
    }
    
    // Addition des retenues
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    
    // Complément à 1
    return (uint16_t)(~sum);
}

// Convertit une adresse IP en format texte en format binaire
int ip_to_binary(const char *ip_str, uint32_t *ip_bin) {
    struct in_addr addr;
    
    if (ip_str == NULL || ip_bin == NULL) {
        return -1;
    }
    
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }
    
    *ip_bin = ntohl(addr.s_addr);
    return 0;
}
