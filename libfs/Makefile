# Target library
lib := libfs.a

# Source files
sources := fs.c disk.c
objects := $(sources:.c=.o)

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -Werror -std=c99
CFLAGS += -MMD -MP

# Dependency files
deps := $(objects:.o=.d)

# Default target
all: $(lib)

# Build the static library
$(lib): $(objects)
	@echo "AR	$@"
	@ar rcs $@ $^

# Pattern rule for object files
%.o: %.c
	@echo "CC	$@"
	@$(CC) $(CFLAGS) -c -o $@ $<

# Include dependency files
-include $(deps)

# Clean rule
clean:
	@echo "CLEAN	$(shell pwd)"
	@rm -f $(objects) $(deps) $(lib)

# Phony targets
.PHONY: all clean