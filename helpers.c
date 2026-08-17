#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>

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

int send_all(int socket_fd, char *message)
{
    int bytes_sent;
    int total_bytes_sent = 0;
    int length = strlen(message);

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

int open_connection(command_line_args args)
{
    int sock_fd;
    struct sockaddr_in target_addr;

    if((sock_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Error: Failed to open Socket");
        exit(1);
    }

    memset(&target_addr, 0, sizeof(target_addr));
    target_addr.sin_family = AF_INET;
    target_addr.sin_port = htons(args.target_port);

    if (inet_pton(AF_INET, args.target_IP, &target_addr.sin_addr) <= 0) {
        perror("Invalid address or address not supported");
        close(sock_fd);
        exit(1);
    }

    if (connect(sock_fd, (struct sockaddr *)&target_addr, sizeof(target_addr)) < 0) {
        perror("Connection failed");
        close(sock_fd);
        exit(1);
    }

    return sock_fd;
}

void send_request(command_line_args args, int sock_fd)
{
    char message[MAX_PAYLOAD_SIZE];

    sprintf(message,"%s\n%s\n%s\n\n", "sender_placeholder", args.directory, args.password);
    
    send_all(sock_fd, message);
}

void accepted_send(command_line_args args, int sock_fd)
{
    char buffer[MAX_PAYLOAD_SIZE];
    recieve_all(sock_fd, buffer);


    if(strcmp(strtok(buffer, "\n"), "1")) print_error_message("Error: Incorrect target password.");
    if(strcmp(strtok(NULL, "\n"), args.target_IP)) print_error_message("Error: Incorrect target response (target could be compromised).");

    if(strcmp(strtok(NULL, "\n"), "sender_placeholder")) print_error_message("Error: Incorrect target response (target could be compromised).");
    if(strcmp(strtok(NULL, "\n"), args.directory)) print_error_message("Error: Incorrect target response (target could be compromised).");
    if(strcmp(strtok(NULL, "\n"), args.password)) print_error_message("Error: Incorrect target response (target could be compromised).");
}

int send_file(command_line_args args, char *file)
{
    FILE *File;
    if((File = fopen(file, "r")) == NULL)
    {
        perror("Error: Given file failed to open.");
        exit(1);
    }

    int sock_fd = open_connection(args);

    send_request(args, sock_fd);

    accepted_send(args, sock_fd);
    
   return 1;

}