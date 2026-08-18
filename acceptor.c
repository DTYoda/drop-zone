#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <dirent.h>

#include "helpers.h"

#define QUEUE_MAX 16

int open_socket(int port)
{
    int socket_fd;
    struct sockaddr_in address;

    if ((socket_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Error: Socket creation failed");
        exit(1);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(port);      

    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("Error: Socket bind failed");
        close(socket_fd);
        exit(1);
    }

    if (listen(socket_fd, QUEUE_MAX) < 0) {
        perror("Error: Socket listen failed");
        close(socket_fd);
        exit(1);
    }
    return socket_fd;
}

int accept_sender_request(command_line_args args, int socket_fd)
{
    int sender_fd;
    struct sockaddr_in address;
    if ((sender_fd = accept(socket_fd, (struct sockaddr *)&address, NULL)) < 0) {
        perror("Error: Failture accepting sender request");
        close(socket_fd);
        exit(1);
    }

    char buffer[MAX_PAYLOAD_SIZE];
    recieve_all(sender_fd, buffer);

    char *sender_name;
    char *directory_name;
    char *password;

    if((sender_name = strtok(buffer, "\n")) == NULL) print_error_message("Error: Sender request not properly formatted");
    if((directory_name = strtok(NULL, "\n")) == NULL) print_error_message("Error: Sender request not properly formatted");
    if((password = strtok(NULL, "\n")) == NULL) print_error_message("Error: Sender request not properly formatted");

    if(strcmp(password, args.password))
    {
        printf("Sender %s requested to send file %s with incorrect password.\n", sender_name, directory_name);
        close(socket_fd);
        accept_sender_request(args, socket_fd);
    }

    printf("Accept %s from %s? (y/n) ", directory_name, sender_name);

    char answer;
    scanf("%c", &answer);

    if(answer == 'n')
    {
        close(sender_fd);
        accept_sender_request(args, socket_fd);
    }

    char response[MAX_PAYLOAD_SIZE];

    sprintf(response, "1\n%s\n%s\n%s\n\n", sender_name, directory_name, args.password);

    send_all(sender_fd, response, strlen(response));

    return sender_fd;
}
