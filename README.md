# Clone de Nmap (CMAP)

```
 ██████╗ ███╗   ███╗ █████╗ ██████╗ 
██╔════╝ ████╗ ████║██╔══██╗██╔══██╗
██║      ██╔████╔██║███████║██████╔╝
██║      ██║╚██╔╝██║██╔══██║██╔═══╝ 
╚██████╗ ██║ ╚═╝ ██║██║  ██║██║     
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
```

Ce projet est une implémentation simplifiée de l'outil Nmap en langage C, capable de scanner des réseaux, détecter des hôtes actifs, scanner les ports ouverts, et identifier les services associés. **Ce projet est conçu pour fonctionner exclusivement sous Linux.**

## Fonctionnalités

- **Découverte d'hôtes** : Ping ICMP pour vérifier si l'hôte est actif, avec fallback TCP pour les environnements où ICMP est bloqué
- **Scan de ports TCP** : Scan TCP Connect pour détecter les ports ouverts
- **Détection de services** : Identification des services courants associés aux ports
- **Multithreading** : Scan simultané de plusieurs ports pour de meilleures performances
- **Serveur de test** : Outil pour tester le scanner sur localhost

## Structure du projet

```
cmap/
├── include/           # Fichiers d'en-tête
│   ├── scanner.h      # Fonctions de scan réseau
│   ├── utils.h        # Fonctions utilitaires
│   └── network.h      # Fonctions réseau bas niveau
├── src/               # Code source
│   ├── main.c         # Point d'entrée du programme
│   ├── scanner.c      # Implémentation du scanner
│   ├── utils.c        # Implémentation des utilitaires
│   ├── network.c      # Implémentation des fonctions réseau
│   └── test_server.c  # Serveur de test pour valider le scanner
├── Makefile           # Configuration de compilation
└── README.md          # Documentation du projet
```

## Prérequis

- Système d'exploitation Linux
- Compilateur GCC
- Make
- Bibliothèques de développement standard de Linux (libc, pthread)

## Compilation

Pour compiler le projet, exécutez les commandes suivantes :

```bash
# Compiler le scanner principal
make

# Compiler le serveur de test
make test_server

# Nettoyer les fichiers compilés
make clean
```

Cela créera les exécutables `nmap_clone` et `test_server` dans le répertoire `bin/`.

## Utilisation

### Scanner principal

```bash
bin/nmap_clone <ip_address> [start_port] [end_port] [options]
```

### Options

- `--verbose` : Affiche des informations détaillées, y compris les ports fermés et filtrés
- `-Pn` : Désactive la détection d'hôte (ping) - **Recommandé pour localhost**
- `--threads <n>` : Nombre de threads à utiliser (défaut: 4, max: 32)
- `--timeout <ms>` : Timeout en millisecondes (défaut: 2000)

### Serveur de test

```bash
bin/test_server
```

Le serveur de test démarre un service TCP sur le port 8888 qui peut être utilisé pour vérifier que le scanner fonctionne correctement.

### Exemples

Scan TCP basique sur localhost avec l'option -Pn (recommandé) :
```bash
bin/nmap_clone 127.0.0.1 -Pn
```

Scan TCP sur un port spécifique (utile pour tester avec le serveur de test) :
```bash
bin/nmap_clone 127.0.0.1 8888 8888 -Pn
```

Scan TCP sur une plage de ports spécifique avec mode verbeux :
```bash
bin/nmap_clone 192.168.1.1 1 1024 -Pn --verbose
```

Scan avec un timeout plus court pour les réseaux rapides :
```bash
bin/nmap_clone 192.168.1.1 -Pn --timeout 500
```

## Fonctionnalités spéciales

### Détection de localhost

Le scanner inclut une logique spéciale pour détecter les ports ouverts sur localhost (127.0.0.1), ce qui améliore la précision des résultats lors des tests locaux.

### Affichage des résultats

Les résultats du scan sont présentés de manière claire avec :
- Liste des ports ouverts (ou tous les ports en mode verbeux)
- Statistiques sur le nombre de ports scannés, ouverts, fermés et filtrés
- Temps d'exécution du scan

## Dépendances

- Bibliothèque pthread pour le multithreading
- Bibliothèques réseau standard de Linux (socket, netinet)
- **Note importante** : Ce programme ne fonctionne que sous Linux et n'est pas compatible avec Windows ou macOS sans modifications importantes

## Licence

Ce projet est distribué sous licence libre.

---

# English Documentation

# Nmap Clone (CMAP)

This project is a simplified implementation of the Nmap tool in C language, capable of scanning networks, detecting active hosts, scanning open ports, and identifying associated services. **This project is designed to work exclusively on Linux.**

## Features

- **Host Discovery**: ICMP ping to check if the host is active, with TCP fallback for environments where ICMP is blocked
- **TCP Port Scanning**: TCP Connect scan to detect open ports
- **Service Detection**: Identification of common services associated with ports
- **Multithreading**: Simultaneous scanning of multiple ports for better performance
- **Test Server**: Tool to test the scanner on localhost

## Prerequisites

- Linux operating system
- GCC compiler
- Make
- Standard Linux development libraries (libc, pthread)

## Project Structure

```
cmap/
├── include/           # Header files
│   ├── scanner.h      # Network scanning functions
│   ├── utils.h        # Utility functions
│   └── network.h      # Low-level network functions
├── src/               # Source code
│   ├── main.c         # Program entry point
│   ├── scanner.c      # Scanner implementation
│   ├── utils.c        # Utilities implementation
│   ├── network.c      # Network functions implementation
│   └── test_server.c  # Test server to validate the scanner
├── Makefile           # Compilation configuration
└── README.md          # Project documentation
```

## Compilation

To compile the project, run the following commands:

```bash
# Compile the main scanner
make

# Compile the test server
make test_server

# Clean compiled files
make clean
```

This will create the `nmap_clone` and `test_server` executables in the `bin/` directory.

## Usage

### Main Scanner

```bash
bin/nmap_clone <ip_address> [start_port] [end_port] [options]
```

### Options

- `--verbose`: Displays detailed information, including closed and filtered ports
- `-Pn`: Disables host detection (ping) - **Recommended for localhost**
- `--threads <n>`: Number of threads to use (default: 4, max: 32)
- `--timeout <ms>`: Timeout in milliseconds (default: 2000)

### Test Server

```bash
bin/test_server
```

The test server starts a TCP service on port 8888 that can be used to verify that the scanner is working correctly.

### Examples

Basic TCP scan on localhost with the -Pn option (recommended):
```bash
bin/nmap_clone 127.0.0.1 -Pn
```

TCP scan on a specific port (useful for testing with the test server):
```bash
bin/nmap_clone 127.0.0.1 8888 8888 -Pn
```

TCP scan on a specific port range with verbose mode:
```bash
bin/nmap_clone 192.168.1.1 1 1024 -Pn --verbose
```

Scan with a shorter timeout for fast networks:
```bash
bin/nmap_clone 192.168.1.1 -Pn --timeout 500
```

## Special Features

### Localhost Detection

The scanner includes special logic to detect open ports on localhost (127.0.0.1), which improves the accuracy of results during local testing.

### Results Display

The scan results are presented clearly with:
- List of open ports (or all ports in verbose mode)
- Statistics on the number of ports scanned, open, closed, and filtered
- Scan execution time

## Dependencies

- Pthread library for multithreading
- Standard Linux network libraries (socket, netinet)
- **Important note**: This program only works on Linux and is not compatible with Windows or macOS without significant modifications

## License

This project is distributed under an open license.
