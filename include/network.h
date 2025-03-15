#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

/**
 * Structure pour les paquets ICMP (ping)
 */
typedef struct {
    uint8_t type;        // Type de message ICMP
    uint8_t code;        // Code du message
    uint16_t checksum;   // Somme de contrôle
    uint16_t id;         // Identifiant
    uint16_t sequence;   // Numéro de séquence
    uint8_t data[32];    // Données (timestamp, etc.)
} icmp_packet_t;

/**
 * Structure pour les paquets TCP
 */
typedef struct {
    uint32_t src_ip;     // Adresse IP source
    uint32_t dst_ip;     // Adresse IP destination
    uint16_t src_port;   // Port source
    uint16_t dst_port;   // Port destination
    uint32_t seq_num;    // Numéro de séquence
    uint32_t ack_num;    // Numéro d'acquittement
    uint8_t data_offset; // Offset des données (taille de l'en-tête)
    uint8_t flags;       // Drapeaux (SYN, ACK, FIN, etc.)
    uint16_t window;     // Taille de la fenêtre
    uint16_t checksum;   // Somme de contrôle
    uint16_t urgent_ptr; // Pointeur de données urgentes
} tcp_packet_t;

// Définition du type SOCKET pour la compatibilité
typedef int SOCKET;
#define INVALID_SOCKET (-1)
#define SOCKET_ERROR (-1)

/**
 * Initialise la bibliothèque réseau
 * 
 * @return 0 en cas de succès, code d'erreur sinon
 */
int init_network();

/**
 * Nettoie les ressources réseau
 */
void cleanup_network();

/**
 * Crée un socket TCP
 * 
 * @return Descripteur de socket en cas de succès, -1 en cas d'erreur
 */
SOCKET create_tcp_socket();

/**
 * Crée un socket UDP
 * 
 * @return Descripteur de socket en cas de succès, -1 en cas d'erreur
 */
SOCKET create_udp_socket();

/**
 * Crée un socket RAW pour les paquets ICMP
 * 
 * @return Descripteur de socket en cas de succès, -1 en cas d'erreur
 */
SOCKET create_raw_socket();

/**
 * Configure le timeout d'un socket
 * 
 * @param sock Descripteur de socket
 * @param timeout_ms Timeout en millisecondes
 * @return 0 en cas de succès, -1 en cas d'erreur
 */
int set_socket_timeout(SOCKET sock, int timeout_ms);

/**
 * Envoie un paquet ICMP Echo Request (ping)
 * 
 * @param sock Descripteur de socket
 * @param dest_ip Adresse IP de destination
 * @param packet Paquet ICMP à envoyer
 * @return 0 en cas de succès, -1 en cas d'erreur
 */
int send_icmp_echo(SOCKET sock, const char *dest_ip, icmp_packet_t *packet);

/**
 * Reçoit un paquet ICMP Echo Reply
 * 
 * @param sock Descripteur de socket
 * @param packet Buffer pour stocker le paquet reçu
 * @param timeout_ms Timeout en millisecondes
 * @return 0 en cas de succès, -1 en cas d'erreur ou timeout
 */
int receive_icmp_reply(SOCKET sock, icmp_packet_t *packet, int timeout_ms);

/**
 * Envoie un paquet TCP SYN
 * 
 * @param sock Descripteur de socket
 * @param dest_ip Adresse IP de destination
 * @param dest_port Port de destination
 * @param packet Paquet TCP à envoyer
 * @return 0 en cas de succès, -1 en cas d'erreur
 */
int send_tcp_syn(SOCKET sock, const char *dest_ip, uint16_t dest_port, tcp_packet_t *packet);

/**
 * Reçoit un paquet TCP
 * 
 * @param sock Descripteur de socket
 * @param packet Buffer pour stocker le paquet reçu
 * @param timeout_ms Timeout en millisecondes
 * @return 0 en cas de succès, -1 en cas d'erreur ou timeout
 */
int receive_tcp_packet(SOCKET sock, tcp_packet_t *packet, int timeout_ms);

/**
 * Calcule la somme de contrôle pour un paquet IP
 * 
 * @param buffer Données du paquet
 * @param size Taille des données
 * @return Somme de contrôle
 */
uint16_t calculate_checksum(uint16_t *buffer, int size);

/**
 * Convertit une adresse IP en format texte en format binaire
 * 
 * @param ip_str Adresse IP en format texte
 * @param ip_bin Adresse IP en format binaire
 * @return 0 en cas de succès, -1 en cas d'erreur
 */
int ip_to_binary(const char *ip_str, uint32_t *ip_bin);

#endif /* NETWORK_H */
