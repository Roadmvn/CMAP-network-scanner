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
- **Scan de ports TCP** : Scan TCP Connect, Scan TCP SYN (nécessite privilèges root)
- **Scan de ports UDP**
- **Détection de services** : Identification des services courants associés aux ports
- **Détection d'OS (basique)** : Tentative d'identification du système d'exploitation basé sur les ports ouverts
- **Multithreading** : Scan simultané de plusieurs ports pour de meilleures performances
- **Serveur de test** : Outil pour tester le scanner sur localhost

## Structure du projet

```
CMAP-network-scanner/
├── include/           # Fichiers d'en-tête (.h)
│   ├── scanner.h
│   ├── utils.h
│   └── network.h
├── src/               # Code source (.c)
│   ├── main.c
│   ├── scanner.c
│   ├── utils.c
│   ├── network.c
│   └── test_server.c
├── obj/               # Fichiers objets compilés (.o) (créé par make)
├── bin/               # Répertoire pour l'exécutable du serveur de test (créé par make)
├── Makefile           # Configuration de compilation
├── cmap               # Exécutable principal (créé par make)
└── README.md          # Documentation du projet
```

## Prérequis

- Système d'exploitation Linux
- Compilateur GCC
- Make
- Bibliothèques de développement standard de Linux (libc, pthread)

## Compilation

Pour compiler le projet, exécutez la commande suivante à la racine du projet :

```bash
# Compiler le scanner principal (cmap)
make
```

Cela créera l'exécutable `cmap` à la racine du projet.

Pour compiler également le serveur de test :

```bash
# Compiler le serveur de test (bin/test_server)
make test_server
```

Pour nettoyer les fichiers compilés et les exécutables :

```bash
# Nettoyer le projet
make clean
```

## Utilisation

### Scanner principal

Exécutez la commande depuis la racine du projet :

```bash
./cmap <ip_address> [start_port] [end_port] [options]
```

**Arguments :**

- `<ip_address>` : Adresse IP cible à scanner.
- `[start_port]` (Optionnel) : Port de début de la plage de scan (défaut : 1).
- `[end_port]` (Optionnel) : Port de fin de la plage de scan (défaut : 1024).

**Options :**

- `-h`, `--help` : Affiche ce message d'aide.
- `--os-detection` : Active la détection (basique) du système d'exploitation.
- `--udp` : Effectue un scan UDP au lieu du scan TCP Connect par défaut.
- `--syn` : Effectue un scan TCP SYN (nécessite des privilèges administrateur/root).
- `--verbose` : Affiche des informations détaillées, y compris tous les ports scannés (ouverts, fermés, filtrés) et les services connus.
- `-Pn` : Désactive la détection d'hôte initiale (ping). Utile si l'hôte bloque les pings.
- `--threads <n>` : Nombre de threads à utiliser pour le scan (défaut: 4, max: 32).
- `--timeout <ms>` : Timeout en millisecondes pour les tentatives de connexion et réponses (défaut: 2000).

### Serveur de test

Si vous avez compilé le serveur de test :

```bash
./bin/test_server
```

Le serveur de test démarre un service TCP sur le port 8888 qui peut être utilisé pour vérifier que le scanner fonctionne correctement.

### Exemples

Scan TCP basique sur localhost (nécessite -Pn car localhost ne répond pas toujours au ping interne) :
```bash
./cmap 127.0.0.1 -Pn
```

Scan TCP sur le port du serveur de test :
```bash
./cmap 127.0.0.1 8888 8888 -Pn
```

Scan TCP des ports 1 à 1024 sur une IP du réseau local, avec mode verbeux et sans ping :
```bash
./cmap 192.168.1.1 1 1024 --verbose -Pn
```

Scan UDP des 100 premiers ports :
```bash
./cmap 192.168.1.1 1 100 --udp -Pn
```

Scan SYN avec 16 threads et timeout court :
```bash
# Attention: nécessite sudo
sudo ./cmap 192.168.1.1 1 1024 --syn --threads 16 --timeout 500 -Pn
```

## Installation (Optionnel)

Si vous souhaitez pouvoir exécuter la commande `cmap` depuis n'importe quel répertoire sans taper `./cmap`, vous pouvez l'installer dans un répertoire inclus dans votre `PATH`.

1.  Exécutez la commande d'installation (copie `cmap` vers `~/.local/bin`) :
    ```bash
    make install
    ```
2.  Assurez-vous que `~/.local/bin` est dans votre `PATH`. Si ce n'est pas le cas, ajoutez la ligne suivante à votre fichier de configuration shell (ex: `~/.zshrc`, `~/.bashrc`) :
    ```bash
    export PATH="$HOME/.local/bin:$PATH"
    ```
3.  Rechargez votre configuration shell (`source ~/.zshrc` ou `source ~/.bashrc`) ou ouvrez un nouveau terminal.

Après cela, vous devriez pouvoir taper `cmap <arguments>` directement.

## Dépendances

- Bibliothèque pthread pour le multithreading
- Bibliothèques réseau standard de Linux (socket, netinet)
- **Note importante** : Ce programme ne fonctionne que sous Linux et n'est pas compatible avec Windows ou macOS sans modifications importantes

## Licence

Ce projet est distribué sous licence libre.

---

# English Documentation

# Nmap Clone (CMAP)

```
 ██████╗ ███╗   ███╗ █████╗ ██████╗ 
██╔════╝ ████╗ ████║██╔══██╗██╔══██╗
██║      ██╔████╔██║███████║██████╔╝
██║      ██║╚██╔╝██║██╔══██║██╔═══╝ 
╚██████╗ ██║ ╚═╝ ██║██║  ██║██║     
 ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     
```

This project is a simplified implementation of the Nmap tool in C language, capable of scanning networks, detecting active hosts, scanning open ports, and identifying associated services. **This project is designed to work exclusively on Linux.**

## Features

- **Host Discovery**: ICMP ping to check if the host is active, with TCP fallback for environments where ICMP is blocked
- **TCP Port Scanning**: TCP Connect scan, TCP SYN scan (requires root privileges)
- **UDP Port Scanning**
- **Service Detection**: Identification of common services associated with ports
- **OS Detection (basic)**: Attempt to identify the operating system based on open ports
- **Multithreading**: Simultaneous scanning of multiple ports for better performance
- **Test Server**: Tool to test the scanner on localhost

## Project Structure

```
CMAP-network-scanner/
├── include/           # Header files (.h)
│   ├── scanner.h
│   ├── utils.h
│   └── network.h
├── src/               # Source code (.c)
│   ├── main.c
│   ├── scanner.c
│   ├── utils.c
│   ├── network.c
│   └── test_server.c
├── obj/               # Compiled object files (.o) (created by make)
├── bin/               # Directory for the test server executable (created by make)
├── Makefile           # Compilation configuration
├── cmap               # Main executable (created by make)
└── README.md          # Project documentation
```

## Prerequisites

- Linux operating system
- GCC compiler
- Make
- Standard Linux development libraries (libc, pthread)

## Compilation

To compile the project, run the following command in the project root:

```bash
# Compile the main scanner (cmap)
make
```

This will create the `cmap` executable in the project root.

To also compile the test server:

```bash
# Compile the test server (bin/test_server)
make test_server
```

To clean compiled files and executables:

```bash
# Clean the project
make clean
```

## Usage

### Main Scanner

Run the command from the project root:

```bash
./cmap <ip_address> [start_port] [end_port] [options]
```

**Arguments:**

- `<ip_address>`: Target IP address to scan.
- `[start_port]` (Optional): Starting port for the scan range (default: 1).
- `[end_port]` (Optional): Ending port for the scan range (default: 1024).

**Options:**

- `-h`, `--help`: Display this help message.
- `--os-detection`: Enable (basic) operating system detection.
- `--udp`: Perform a UDP scan instead of the default TCP Connect scan.
- `--syn`: Perform a TCP SYN scan (requires administrator/root privileges).
- `--verbose`: Display detailed information, including all scanned ports (open, closed, filtered) and known services.
- `-Pn`: Disable initial host discovery (ping). Useful if the host blocks pings.
- `--threads <n>`: Number of threads to use for scanning (default: 4, max: 32).
- `--timeout <ms>`: Timeout in milliseconds for connection attempts and responses (default: 2000).

### Test Server

If you compiled the test server:

```bash
./bin/test_server
```

The test server starts a TCP service on port 8888 that can be used to verify that the scanner is working correctly.

### Examples

Basic TCP scan on localhost (requires -Pn as localhost might not respond to internal ping):
```bash
./cmap 127.0.0.1 -Pn
```

TCP scan on the test server port:
```bash
./cmap 127.0.0.1 8888 8888 -Pn
```

Scan TCP ports 1 to 1024 on a local network IP, with verbose mode and no ping:
```bash
./cmap 192.168.1.1 1 1024 --verbose -Pn
```

UDP scan of the first 100 ports:
```bash
./cmap 192.168.1.1 1 100 --udp -Pn
```

SYN scan with 16 threads and short timeout:
```bash
# Warning: requires sudo
sudo ./cmap 192.168.1.1 1 1024 --syn --threads 16 --timeout 500 -Pn
```

## Installation (Optional)

If you want to run the `cmap` command from any directory without typing `./cmap`, you can install it in a directory included in your `PATH`.

1.  Run the install command (copies `cmap` to `~/.local/bin`):
    ```bash
    make install
    ```
2.  Ensure `~/.local/bin` is in your `PATH`. If not, add the following line to your shell configuration file (e.g., `~/.zshrc`, `~/.bashrc`):
    ```bash
    export PATH="$HOME/.local/bin:$PATH"
    ```
3.  Reload your shell configuration (`source ~/.zshrc` or `source ~/.bashrc`) or open a new terminal.

After this, you should be able to type `cmap <arguments>` directly.

## Dependencies

- pthread library for multithreading
- Standard Linux network libraries (socket, netinet)
- **Important Note**: This program only works on Linux and is not compatible with Windows or macOS without significant modifications

## License

This project is distributed under a free license.
