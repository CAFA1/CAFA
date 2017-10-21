#include <stdio.h>
#include <zlib.h>
int match(int a,int b)
{
  return a==b;
}
void sayhello(char*buffer)
{
      
  int crcfile = *(long unsigned int*)((char*)(&buffer[20]));
  int crc_code = crc32(0, (const Bytef*)buffer, 20);  
  

  if(match(crc_code,crcfile))
  {
    printf("match\n");
    
  }
  else
  {
    printf("no match\n");
  }
  return;
}