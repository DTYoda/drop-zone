#include "helpers.h"

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
    
    send_all(sock_fd, message, strlen(message));
}

void accepted_send(command_line_args args, int sock_fd)
{
    char buffer[MAX_PAYLOAD_SIZE];
    recieve_all(sock_fd, buffer);


    if(strcmp(strtok(buffer, "\n"), "1")) print_error_message("Error: Incorrect target password.");

    if(strcmp(strtok(NULL, "\n"), "sender_placeholder")) print_error_message("Error: Incorrect target response (target could be compromised).");
    if(strcmp(strtok(NULL, "\n"), args.directory)) print_error_message("Error: Incorrect target response (target could be compromised).");
    if(strcmp(strtok(NULL, "\n"), args.password)) print_error_message("Error: Incorrect target response (target could be compromised).");
}

int send_file(char *file, int sock_fd)
{
    FILE *File;
    if((File = fopen(file, "rb")) == NULL)
    {
        perror("Error: Given file failed to open.");
        exit(1);
    }

    char buffer[MAX_PAYLOAD_SIZE] = {0};
    int file_bytes_read = 0;
    while((file_bytes_read = fread(buffer, 1, MAX_PAYLOAD_SIZE, File)) > 0)
    {
        send_all(sock_fd, buffer, file_bytes_read);
        memset(buffer, 0, MAX_PAYLOAD_SIZE);
    }
    
    fclose(File);
    
    return 0;

}

int send_directory(char *dir, int sock_fd)
{
    DIR *Dir = opendir(dir);
    struct dirent *entry;
    char path[1024];

    if (!dir) print_error_message("Error: could not open directory");

    while ((entry = readdir(Dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) 
        {
            snprintf(path, sizeof(path), "%s/%s", dir, entry->d_name);
            if (entry->d_type == DT_DIR) {
                
                send_directory(path, sock_fd);
            }
            else
            {
                send_file(path, sock_fd);
            }
        }
    }
    closedir(Dir);
    return 0;
}

int handle_send(command_line_args args)
{
    int sock_fd = open_connection(args);

    send_request(args, sock_fd);

    accepted_send(args, sock_fd);

    send_directory(args.directory, sock_fd);

    return 0;
}

