# OS
ubuntu 12.04 (Other OS may have problems.)
# taint_checksum
longlong's checksum taint analysis based on bap's pintraces.  
note that there is the other branch (taint branch).  
# get checksum point command
python schedule_identify.py 1 30 libpng /usr/local/bin/magick  
# AFL Fuzz command
cd pintraces/sample/png  
AFL_INST_LIBS=1 afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@  
