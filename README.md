# OS
ubuntu 12.04 (Other OS may have problems.)
# taint_checksum
longlong's checksum taint analysis based on bap's pintraces.
# test command
python schedule_jnz.py 1 20 mywps ./mywps

python schedule_identify.py 1 30 libpng /usr/local/bin/magick

python schedule_udp.py 0x10 0x80 abcd /usr/local/sbin/tcpdump

python schedule_ip.py 0x5 0x60 abcd /usr/local/sbin/tcpdump

python schedule_igmp.py 0x3 0x60 abcd /usr/local/sbin/tcpdump

python schedule_tcp.py 0x3 0x53 abcd /usr/local/sbin/tcpdump


