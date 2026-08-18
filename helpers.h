#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <dirent.h>

#define MAX_PAYLOAD_SIZE 1024

typedef struct {
    int is_sender;
    char *directory;
    char *group;
    char *password;
    char *target_IP;
    int target_port;
    char *output;
} command_line_args;

void print_help_message(const char *error);

void print_error_message(const char *error);

command_line_args extract_command_line(int argc, char *argv[]);

int send_all(int socket_fd, char *message, int length);

int recieve_all(int sock_fd, char *buffer);