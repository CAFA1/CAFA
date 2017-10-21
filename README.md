# OS
ubuntu 12.04 (Other OS may have problems.)
# require and configure
echo core >/proc/sys/kernel/core_pattern  
echo 0 >/proc/sys/kernel/randomize_va_space  
set  AFL_PATH to the root directory of afl-fuzz and set AFL_INST_LIBS to 1.
```
set|grep AFL
AFL_INST_LIBS=1
AFL_PATH=/home/bap/Download/afl-2.51b
```
install imagemagick tcpdump afl-fuzz

# taint_checksum
longlong's checksum taint analysis based on bap's pintraces.
# test command
python schedule_jnz.py 1 20 mywps ./mywps  
python schedule_identify.py 1 30 libpng /usr/local/bin/magick  
python schedule_udp.py 0x10 0x80 abcd /usr/local/sbin/tcpdump  
python schedule_ip.py 0x5 0x60 abcd /usr/local/sbin/tcpdump  
python schedule_igmp.py 0x3 0x60 abcd /usr/local/sbin/tcpdump  
python schedule_tcp.py 0x3 0x53 abcd /usr/local/sbin/tcpdump

# afl-fuzz
cd pintraces/sample/lib/  
make  
make test  
make test_fuzz  


