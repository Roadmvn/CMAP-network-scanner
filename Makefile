# Variables
CC = gcc
CFLAGS = -Wall -Wextra -I./include
LDFLAGS = -lpthread
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin
TARGET = $(BIN_DIR)/nmap_clone

# Sources et objets
SRCS = $(wildcard $(SRC_DIR)/*.c)
SRCS_MAIN = $(filter-out $(SRC_DIR)/test_server.c, $(SRCS))
OBJS_MAIN = $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRCS_MAIN))

# Règle par défaut
all: directories $(TARGET)

# Création des répertoires nécessaires
directories:
	@mkdir -p $(OBJ_DIR)
	@mkdir -p $(BIN_DIR)

# Compilation du programme principal
$(TARGET): $(OBJS_MAIN)
	$(CC) -o $@ $^ $(LDFLAGS)

# Règle générique pour compiler les fichiers sources
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

# Ajout de la cible pour le serveur de test
test_server: directories $(OBJ_DIR)/test_server.o
	$(CC) -o $(BIN_DIR)/test_server $(OBJ_DIR)/test_server.o $(LDFLAGS)

$(OBJ_DIR)/test_server.o: $(SRC_DIR)/test_server.c
	$(CC) $(CFLAGS) -c $< -o $@

# Nettoyage
clean:
	@rm -rf $(OBJ_DIR)
	@rm -rf $(BIN_DIR)

# Règle pour éviter de supprimer les fichiers intermédiaires
.PRECIOUS: $(OBJ_DIR)/%.o

.PHONY: all clean directories test_server
