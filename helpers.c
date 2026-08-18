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

void print_help_message(const char *error)
{
    FILE *stream = NULL;
    if(error != NULL)
    {
        stream = stderr;
        fprintf(stream, "Error: %s\n\n", error);
    }
    else
    {
        stream = stdout;
    }
    fprintf(stream, "Ussage: ./drop-zone [OPTION]\n"
                    "Easily send and recieve files from users in a LAN.\n\n"
                    "Options:\n"
                    "  -h, --help               print the help message.\n"
                    "  -f, --file=FILE          file or directory to send.\n"
                    "  -t, --target=TARGET      device name to send files to.\n"
                    "  -g, --group=GROUP        group name to send files to.\n"
                    "  -s, --send               send FILE to TARGET or GROUP.\n"
                    "  -o, --output=OUTPUT      directory to save recieved files.\n" 
                    "  -a, --accept             accept files from others and save in OUTPUT directory.\n"
                    "  -p, --password=PASSWORD  password for TARGET or GROUP to send files, if needed.\n"
          );
    if(error == NULL) exit(0);
    else exit(1);
}

void print_error_message(const char *error)
{
    perror(error);
    exit(1);
}

void extract_IP(char *target, command_line_args args)
{
    char *tmp = strdup(target);
    char *end;
    char *port_string;

    args.target_IP = strtok(tmp, ":");
    port_string = strtok(NULL, ":");

    args.target_port = (int) strtol(port_string, &end, 10);

    free(tmp);

    if(args.target_IP == NULL || args.target_port == -1 || end == port_string)
    {
        perror("Error: Failed to parse target IP and Port.");
        exit(1);
    }
}

command_line_args extract_command_line(int argc, char *argv[])
{
    command_line_args args = {0};
    args.is_sender = -1;
    args.target_port = -1;

    int opt;

    struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"file", required_argument, 0, 'f'},
        {"send", no_argument, 0, 's'},
        {"accept", no_argument, 0, 'a'},
        {"group", required_argument, 0, 'g'},
        {"password", required_argument, 0, 'p'},
        {"target", required_argument, 0, 't'},
        {"output", required_argument, 0, 'o'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "hf:sag:p:t:o:", long_options, NULL)) != -1) {
        switch (opt) {
            case 'h':
                print_help_message(NULL);
            case 'f':
                args.directory = strdup(optarg);
                break;
            case 'g':
                args.group = strdup(optarg);
                break;
            case 'p':
                args.password = strdup(optarg);
                break;
            case 't':
                extract_IP(optarg, args);
                break;
            case 'o':
                args.output = strdup(optarg);
                break;
            case 's':
                if(args.is_sender != -1) print_help_message("Cannot be both a sender and accepter.");
                args.is_sender = 1;
                break;
            case 'a':
                if(args.is_sender != -1) print_help_message("Cannot be both a sender and accepter.");
                args.is_sender = 0;
                break;
        }
    }

    if(args.is_sender == 1)
    {
        if(args.directory == NULL) print_help_message("Missing file/directory to send.");
        if(args.target_IP == NULL) print_help_message("Missing target to send files to.");
        if(args.password == NULL) print_help_message("Missing password for target.");
    }
    else if(args.is_sender == 0)
    {
        if(args.output == NULL) print_help_message("Missing directory to place recieved files.");
    }
    else print_help_message("Missing either --send or --accept.");

    return args;
}

int send_all(int socket_fd, char *message, int length)
{
    int bytes_sent;
    int total_bytes_sent = 0;

    while(length > 0)
    {
        bytes_sent = send(socket_fd, message + total_bytes_sent, length, 0);
        if(bytes_sent < 0)
        {
            perror("Error: failed to transmit request header");
            exit(1);
        }
        length -= bytes_sent;
        total_bytes_sent += bytes_sent;
    }

    return total_bytes_sent;
}

int recieve_all(int sock_fd, char *buffer)
{
    int remaining = MAX_PAYLOAD_SIZE;
    int recieved;
    int total_recieved = 0;
    
    while((recieved = recv(sock_fd, buffer + total_recieved, remaining, 0)) > 0)
    {
        total_recieved += recieved;
        remaining -= recieved;

        if(total_recieved >= 2 && buffer[total_recieved - 1] == '\n' && buffer[total_recieved - 2] == '\n')
        {
            return 0;
        }
    }

    perror("Error: Failed to recieve full response from target.");
    exit(1);
}

