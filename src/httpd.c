#include "stdio.h"

int main(int argc, char **argv)
{
    if (argc > 1)
    {
        for (int i = 1; i < argc; i++)
        {
            printf("Argv[%d]: %s\n", i, argv[i]);
        }
    }
    printf("Hello world!\n");
    return 0;
}
