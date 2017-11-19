#include "hello.h"  
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

//void sayhello(char*a);
int main(int argc, char **argv)  
{  
    int fd;
    char  buffer[28] = {0};
    printf("%s\n%s\n", argv[0], argv[1]);
    fd = open(argv[1], O_RDONLY);
    read(fd, buffer, 24);
    sayhello(buffer);
    return 0;  
}  