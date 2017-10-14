#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <zlib.h>  

int main(int argc, char **argv)
{
  int fd;
  char  buffer[28] = {0};
  //fd = open("serial.txt", O_RDONLY);
 long unsigned int crc_code;
 long unsigned int crcfile;
 int i;
  int buffer_sz;  
    printf("%s\n%s\n", argv[0], argv[1]);
    
    
    fd = open(argv[1], O_RDONLY);
    read(fd, buffer, 24);
     //buffer_sz = strlen(buffer);  
     crcfile = *(long unsigned int*)((char*)(&buffer[20]));
     crc_code = crc32(0, (const Bytef*)buffer, 20);  
     //for(i=0;i<20;i++) 
    // {
     // crc_code = crc_code + (int)(buffer[i]);
     //}
      
    printf("crc_code : %lx\n", crc_code);  
    printf("crc_code_file : %lx\n", crcfile);   
    if(crc_code==crcfile)
    {
      printf("match\n");
    }
    close(fd);  
      
    return 0;
  
}


