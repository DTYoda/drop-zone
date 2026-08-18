# Define variables for flexibility
CC = gcc
CFLAGS = -Wall -g -Wextra

# The first target is the default one when you just type 'make'
all: drop-zone

# Link object files to create the final executable
drop-zone: main.o helpers.o sender.o acceptor.o
	$(CC) $(CFLAGS) -o drop-zone main.o helpers.o sender.o acceptor.o

# Compile main.c into main.o
main.o: main.c helpers.h
	$(CC) $(CFLAGS) -c main.c

helpers.o: helpers.c helpers.h
	$(CC) $(CFLAGS) -c helpers.c

sender.o: sender.c sender.h
	$(CC) $(CFLAGS) -c sender.c

acceptor.o: acceptor.c acceptor.h
	$(CC) $(CFLAGS) -c acceptor.c

# Clean up build files
clean:
	rm -f *.o drop-zone