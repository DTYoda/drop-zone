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

void print_help_message(const char *error);

command_line_args extract_command_line(int argc, char *argv[]);