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
set  AFL_PATH to the root directory of afl-fuzz and set AFL_INST_LIBS to 1.
```
export AFL_INST_LIBS=1
export AFL_PATH=/home/bap/Download/afl-2.51b
```
install the test software and afl-fuzz

# test command
1. imagemagick   
```
python schedule_identify.py 8 13 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad.png    
python schedule_identify.py 0x20 881 libpng /usr/local/bin/magick identify ./sample/png/good.png ./sample/png/bad2.png 
```

2. pngcheck   
```
python schedule_identify.py 8 13 pngcheck /usr/bin/pngcheck " " ./sample/png/good.png ./sample/png/bad.png  
python schedule_identify.py 0x20 881 pngcheck /usr/bin/pngcheck " " ./sample/png/good.png ./sample/png/bad.png  
```

3. gz  
```
python schedule_identify.py 0 0x21 gzip /usr/local/bin/gzip -d ./sample/gz/good.txt.gz ./sample/gz/bad.txt.gz  
``` 
 
4. unzip  
``` 
python schedule_identify.py 0 0x26 unzip /usr/bin/unzip " " ./sample/zip/good.zip ./sample/zip/bad.zip
```

5. rar
```
python schedule_identify.py 7 13 rar /usr/local/bin/rar e ./sample/rar/good.rar ./sample/rar/bad2.rar  
python schedule_identify.py 0x14 0x34 rar /usr/local/bin/rar e ./sample/rar/good.rar ./sample/rar/bad3.rar 
``` 

6. pcap  
    6.1 udp checksum point  
    ```
    python schedule_identify.py 0x5e 8 tcpdump /usr/local/sbin/tcpdump " -v -r  " ./sample/udp/good_udp.pcap ./sample/udp/bad_udp.pcap 
    ``` 
    6.2 tcp checksum point  
    ```
    python schedule_identify.py 0x4a 20 tcpdump /usr/local/sbin/tcpdump " -v -r  " ./sample/tcp/good_tcp.pcap ./sample/tcp/bad_tcp.pcap  
    ```
    6.3 ip checksum point  
    ```
    python schedule_identify.py 0x36 20 tcpdump /usr/local/sbin/tcpdump " -v -r  " ./sample/ip/good_ip.pcap ./sample/ip/bad_ip.pcap  
    ```
    6.3 igmp checksum point  
    ```
    python schedule_identify.py 0x4e 16 tcpdump /usr/local/sbin/tcpdump " -v -r  " ./sample/igmp/good_igmp.pcap ./sample/igmp/bad_igmp.pcap 
    ``` 

# afl-fuzz my own sample
cd pintraces/sample/lib/  
make  
make test  
make test_fuzz  
# afl-fuzz libpng
1. before patch  
cd pintraces/sample/png  
afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@
2. after patch  
cd pintraces/sample/png   
cp ../libpng12.so.0.46.0 /usr/local/lib/libpng12.so.0.46.0  
afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@