#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <stdbool.h>
#include <string.h>

#include "helpers.h"

int main(int argc, char *argv[])
{
    command_line_args args = extract_command_line(argc, argv);
    return 0;
}