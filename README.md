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
python schedule_identify.py CRC32-S libz.so crc32 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad.png    
python schedule_identify.py Taint-S 8 0x16 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad.png
```
2. optipng  
```
python schedule_identify.py 8 13 libpng ./sample/png/optipng/optipng " " ./sample/png/bak/good.png ./sample/png/bak/bad.png

```
3. pngcheck   
```
python schedule_identify.py 8 13 pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/png/good.png ./sample/png/bad.png  
python schedule_identify.py 0x20 881 pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/png/good.png ./sample/png/bad.png  
```

4. gz  
```
python schedule_identify.py 0 0x21 gzip ./sample/gz/origin/gzip -d ./sample/gz/good.txt.gz ./sample/gz/bad.txt.gz  
``` 
 
5. unzip  
``` 
python schedule_identify.py 0 0x26 unzip ./sample/zip/origin/unzip " " ./sample/zip/good.zip ./sample/zip/bad.zip
```

6. rar
```
python schedule_identify.py 7 13 rar ./sample/rar/origin/rar e ./sample/rar/good.rar ./sample/rar/bad2.rar  
``` 

7. tar
```
python schedule_identify.py 0 0x159 tar ./sample/tar/origin/tar -tf ./sample/tar/good.tar ./sample/tar/bad.tar  

``` 

8. tcpdump  
    8.1 udp checksum point  
    ```
    python schedule_identify.py 0x5e 8 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/udp/good_udp.pcap ./sample/udp/bad_udp.pcap 
    ``` 
    8.2 tcp checksum point  
    ```
    python schedule_identify.py 0x4a 20 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/tcp/good_tcp.pcap ./sample/tcp/bad_tcp.pcap  
    ```
    8.3 ip checksum point  
    ```
    python schedule_identify.py 0x36 20 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/ip/good_ip.pcap ./sample/ip/bad_ip.pcap  
    ```
    8.4 igmp checksum point  
    ```
    python schedule_identify.py 0x4e 16 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/igmp/good_igmp.pcap ./sample/igmp/bad_igmp.pcap 
    ``` 

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