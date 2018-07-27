# CAFA: A Checksum-Aware Fuzzing Assistant For More Coverage

# OS
Ubuntu 12.04 32bit (Other OS may have problems.)

# Install
```
git clone https://github.com/CAFA1/CAFA.git  
cd pintraces  
make 
``` 

# Require and configure
echo core >/proc/sys/kernel/core_pattern    
echo 0 >/proc/sys/kernel/randomize_va_space    
Install the test software and afl-fuzz.  
Set  AFL_PATH env to the root directory of afl-fuzz.  
install capstone and the python binding
  

# Commands to identify checksum points
```
python schedule_identify.py strategy taint_start(CksumLib) taint_length(CkmsumFunc) module_name elf_path ext_command good_sample bad_sample
    stategy: CRC32-S strategy or Taint-S strategy
    taint_start: the starting offset of the taint source.
    taint_length: the length of the taint source.
    module_name: the name of the module where the checksum check is located.
    elf_path: the path of the test program.
    ext_command: the options of the test program.
    good_sample: the path of the well-formed sample.
    bad_sample: the path of the malformed sample.
```
1. ImageMagick   
```
1. Identify the crc32 checksum point:
python schedule_identify.py CRC32-S libz.so crc32 0 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad.png    
python schedule_identify.py Taint-S 8 0x16 0 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad.png
python schedule_identify.py Taint-S 0x1d 4 0 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad.png

2. Identify the crc32 checksum point:
python schedule_convert.py Taint-S 0x1aef 4 0 libpng /usr/local/bin/magick convert ./sample/adobe/good.png ./sample/adobe/bad_crc.png 

3. Identify the Adler32 checksum point:
python schedule_convert.py Taint-S 0x1aeb 4 0 libz.so /usr/local/bin/magick convert  ./sample/adobe/good.png ./sample/adobe/bad_adler.png 

```
2. optipng  
```
1. Identify the crc32 checksum point:
python schedule_identify.py CRC32-S libz.so crc32 0 libpng ./sample/png/optipng/optipng " " ./sample/png/bak/good.png ./sample/png/bak/bad.png
python schedule_identify.py Taint-S 8 0x16 0 libpng ./sample/png/optipng/optipng " " ./sample/png/bak/good.png ./sample/png/bak/bad.png
python schedule_identify.py Taint-S 0x1d 4 0 libpng ./sample/png/optipng/optipng " " ./sample/png/bak/good.png ./sample/png/bak/bad.png

2. Identify the crc32 checksum point:
python schedule_identify.py Taint-S 0x1aef 4 0 libpng ./sample/png/optipng/optipng " " ./sample/adobe/good.png ./sample/adobe/bad_crc.png 

3. Identify the Adler32 checksum point:
python schedule_identify.py Taint-S 0x1aeb 4 0 libz.so ./sample/png/optipng/optipng " " ./sample/adobe/good.png ./sample/adobe/bad_adler.png 

```
3. pngcheck   
```
1. Identify the crc32 checksum point:
python schedule_identify.py CRC32-S libz.so crc32 0 pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/png/good.png ./sample/png/bad.png  
python schedule_identify.py Taint-S 8 0x16 0 pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/png/good.png ./sample/png/bad.png 
python schedule_identify.py Taint-S 0x1d 4 0 pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/png/good.png ./sample/png/bad.png 

2. Identify the crc32 checksum point:
python schedule_identify.py Taint-S 0x1aef 4 0 pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/adobe/good.png ./sample/adobe/bad_crc.png 

3. Identify the Adler32 checksum point:
python schedule_identify.py Taint-S 0x1aeb 4 0 libz.so ./sample/png/optipng/optipng " " ./sample/adobe/good.png ./sample/adobe/bad_crc_adler.png 

```

4. gzip  
```
python schedule_identify.py Taint-S 0 0x21 1 gzip ./sample/gz/origin/gzip -d ./sample/gz/good.txt.gz ./sample/gz/bad.txt.gz 
python schedule_identify.py Taint-S 0x19 4 1 gzip ./sample/gz/origin/gzip -d ./sample/gz/good.txt.gz ./sample/gz/bad.txt.gz 

``` 
 
5. unzip  
``` 
python schedule_identify.py Taint-S 0xe 4 0 unzip ./sample/zip/origin/unzip " " ./sample/zip/good.zip ./sample/zip/bad.zip
python schedule_identify.py Taint-S 0 0x26 0 unzip ./sample/zip/origin/unzip " " ./sample/zip/good.zip ./sample/zip/bad.zip
```

6. rar
```
python schedule_identify.py Taint-S 0x14 2 0 rar ./sample/rar/origin/rar e ./sample/rar/good.rar ./sample/rar/bad.rar 
python schedule_identify.py Taint-S 0x14 0x34 0 rar ./sample/rar/origin/rar e ./sample/rar/good.rar ./sample/rar/bad.rar 

``` 

7. tar
```
python schedule_identify.py Taint-S 0 500 0 tar ./sample/tar/origin/tar -tf ./sample/tar/good.tar ./sample/tar/bad.tar  
python schedule_identify.py Taint-S 148 8 0 tar ./sample/tar/origin/tar -tf ./sample/tar/good.tar ./sample/tar/bad.tar  

``` 

8. tcpdump  
    8.1 udp checksum point  
    ```
    python schedule_identify.py Taint-S 0x5e 8 0 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/udp/good_udp.pcap ./sample/udp/bad_udp.pcap 
    python schedule_identify.py Taint-S 0x64 2 0 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/udp/good_udp.pcap ./sample/udp/bad_udp.pcap 
    ``` 
    8.2 tcp checksum point  
    ```
    python schedule_identify.py Taint-S 0x4a 20 0 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/tcp/good_tcp.pcap ./sample/tcp/bad_tcp.pcap 
    python schedule_identify.py Taint-S 0x5a 2 0 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/tcp/good_tcp.pcap ./sample/tcp/bad_tcp.pcap 
    ```
    8.3 ip checksum point  
    ```
    python schedule_identify.py Taint-S 0x36 20 0 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/ip/good_ip.pcap ./sample/ip/bad_ip.pcap  
    python schedule_identify.py Taint-S 0x40 2 0 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/ip/good_ip.pcap ./sample/ip/bad_ip.pcap 
    ```
    8.4 igmp checksum point  
    ```
    python schedule_identify.py Taint-S 0x4e 16 0 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/igmp/good_igmp.pcap ./sample/igmp/bad_igmp.pcap 
    python schedule_identify.py Taint-S 0x50 2 0 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/igmp/good_igmp.pcap ./sample/igmp/bad_igmp.pcap 
    ``` 
# Commands to patch at the checksum point   
'''
python patch_checksum.py file_name checksum_point  

python patch_checksum.py patch_sample/libz/libz.so.1.2.3.4 0x922e
python patch_checksum.py patch_sample/libpng/libpng12.so.0.46.0 0x7972  
   
python patch_checksum.py patch_sample/pngcheck/pngcheck 0x11df6    
python patch_checksum.py patch_sample/gzip/gzip 0x978e  
python patch_checksum.py patch_sample/unzip/unzip 0x70d6
python patch_checksum.py patch_sample/tar/tar 0x16eae
python patch_checksum.py patch_sample/rar/rar 0xe728 

'''
You can also patch the same program multiple times.   
'''
patching at the udp checksum point:
python patch_checksum.py patch_sample/tcpdump/tcpdump 0x73115  
patching at the tcp checksum point:
python patch_checksum.py patch_sample/tcpdump/tcpdump.patch 0x6e68b
patching at the ip checksum point:
python patch_checksum.py patch_sample/tcpdump/tcpdump.patch.patch 0x31615
patching at the ip checksum point:
python patch_checksum.py patch_sample/tcpdump/tcpdump.patch.patch.patch 0x30146

'''

# AFL Fuzz ImageMagick command
1. Before patching  
```
cd pintraces/sample/png  
afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@  
```
2. After patching  
```
cd pintraces/sample/png  
cp ./libpng/patch/libpng12.so.0.46.0 /usr/local/lib/libpng12.so.0.46.0    
afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@  
``` 
# AFL Fuzz optipng command
1. Before patching  
```
cd pintraces/sample/png  
afl-fuzz -i in -o out -Q -- ./optipng/optipng  @@  
```
2. After patching  
```
cd pintraces/sample/png  
cp ./libpng/patch/libpng12.so.0.46.0 /usr/local/lib/libpng12.so.0.46.0    
afl-fuzz -i in -o out -Q -- ./optipng/optipng  @@   
``` 