#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>

typedef struct {
    int is_sender;
    char *directory;
    char *group;
    char *password;
    char *target;
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

command_line_args extract_command_line(int argc, char *argv[])
{
    command_line_args args = {0};
    args.is_sender = -1;

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
                args.directory = (char *) malloc(sizeof(char) * strlen(optarg) + 1);
                strcpy(args.directory, optarg);
                break;
            case 'g':
                args.group = (char *) malloc(sizeof(char) * strlen(optarg) + 1);
                strcpy(args.group, optarg);
                break;
            case 'p':
                args.password = (char *) malloc(sizeof(char) * strlen(optarg) + 1);
                strcpy(args.password, optarg);
                break;
            case 't':
                args.target = (char *) malloc(sizeof(char) * strlen(optarg) + 1);
                strcpy(args.target, optarg);
                break;
            case 'o':
                args.output = (char *) malloc(sizeof(char) * strlen(optarg) + 1);
                strcpy(args.output, optarg);
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
        if(args.target == NULL) print_help_message("Missing target to send files to.");
        if(args.password == NULL) print_help_message("Missing password for target.");
    }
    else if(args.is_sender == 0)
    {
        if(args.output == NULL) print_help_message("Missing directory to place recieved files.");
    }
    else print_help_message("Missing either --send or --accept.");

    return args;
}