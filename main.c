#include "sender.h"

int main(int argc, char *argv[])
{
    command_line_args args = extract_command_line(argc, argv);

    if(args.is_sender)
    {
        handle_send(args);
    }
    else
    {
    }
    return 0;
}