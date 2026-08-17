# Define variables for flexibility
CC = gcc
CFLAGS = -Wall -g -Wextra -02

# The first target is the default one when you just type 'make'
all: drop-zone

# Link object files to create the final executable
drop-zone: main.o helpers.o
	$(CC) $(CFLAGS) -o drop-zone main.o helpers.o

# Compile main.c into main.o
main.o: main.c helpers.h
	$(CC) $(CFLAGS) -c main.c

# Compile functions.c into functions.o
functions.o: helpers.c helpers.h
	$(CC) $(CFLAGS) -c helpers.c

# Clean up build files
clean:
	rm -f *.o drop-zone