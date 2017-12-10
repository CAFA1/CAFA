# taint_checksum
longlong's checksum taint analysis system.

# OS
ubuntu 12.04 (Other OS may have problems.)

# Install
```
git clone https://github.com/zhuceyongdela1234/taint_checksum.git  
git checkout taint
cd pintraces  
make 
``` 

# require and configure
echo core >/proc/sys/kernel/core_pattern  
echo 0 >/proc/sys/kernel/randomize_va_space  
set  AFL_PATH env to the root directory of afl-fuzz.  
install the test software and afl-fuzz.  

# test command
1. imagemagick   
```
python schedule_identify.py 8 13 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad.png    
python schedule_identify.py 0x20 881 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad2.png 
```

2. pngcheck   
```
python schedule_identify.py 8 13 pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/png/good.png ./sample/png/bad.png  
python schedule_identify.py 0x20 881 pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/png/good.png ./sample/png/bad.png  
```

3. gz  
```
python schedule_identify.py 0 0x21 gzip ./sample/gz/origin/gzip -d ./sample/gz/good.txt.gz ./sample/gz/bad.txt.gz  
``` 
 
4. unzip  
``` 
python schedule_identify.py 0 0x26 unzip ./sample/zip/origin/unzip " " ./sample/zip/good.zip ./sample/zip/bad.zip
```

5. rar
```
python schedule_identify.py 7 13 rar ./sample/rar/origin/rar e ./sample/rar/good.rar ./sample/rar/bad2.rar  
``` 

6. tar
```
python schedule_identify.py 0 0x159 tar ./sample/tar/origin/tar -tf ./sample/tar/good.tar ./sample/tar/bad.tar  

``` 

7. pcap  
    7.1 udp checksum point  
    ```
    python schedule_identify.py 0x5e 8 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/udp/good_udp.pcap ./sample/udp/bad_udp.pcap 
    ``` 
    7.2 tcp checksum point  
    ```
    python schedule_identify.py 0x4a 20 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/tcp/good_tcp.pcap ./sample/tcp/bad_tcp.pcap  
    ```
    7.3 ip checksum point  
    ```
    python schedule_identify.py 0x36 20 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/ip/good_ip.pcap ./sample/ip/bad_ip.pcap  
    ```
    7.4 igmp checksum point  
    ```
    python schedule_identify.py 0x4e 16 tcpdump ./sample/tcp/origin/tcpdump " -v -r  " ./sample/igmp/good_igmp.pcap ./sample/igmp/bad_igmp.pcap 
    ``` 

# afl-fuzz my own sample
cd pintraces/sample/lib/  
make  
make test  
make test_fuzz  
# 1. afl-fuzz ImageMagick
```
1. before patch   
afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@
2. after patch   
LD_PRELOAD=./libpng/patch/libpng12.so.0.46.0 afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@
```
# 2. afl-fuzz rar
```
1. before patch   
afl-fuzz -i in -o out -Q -- ./origin/rar identify @@
2. after patch   
afl-fuzz -i in -o out -Q -- ./patch/rar identify @@
```
# 3. afl-fuzz pngcheck
```
1. before patch   
afl-fuzz -i in -o out -Q -- origin_pngcheck/pngcheck -pvv identify @@
2. after patch   
afl-fuzz -i in -o out -Q -- patch_pngcheck/pngcheck -pvv identify @@
```