# Compiler and flags
CC      := gcc
CFLAGS  := -Wall
INCLUDES:= -Iinclude

SRC_DIR := src
OBJDIR  := obj
BINDIR  := bin

SRC := $(shell find $(SRC_DIR) -name "*.c")
OBJ := $(patsubst $(SRC_DIR)/%.c,$(OBJDIR)/%.o,$(SRC))

TARGET := $(BINDIR)/crypto_demo

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJ) | $(BINDIR)
	$(CC) $(CFLAGS) $(OBJ) -o $@ -lmcrypt  # link mcrypt here

$(OBJDIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

$(BINDIR):
	@mkdir -p $(BINDIR)

clean:
	rm -rf $(OBJDIR) $(BINDIR)/crypto_demo
