# note that there is the other branch (taint branch).   
# This branch is for software with crc32 checksum, while the taint branch is for general checksum.  

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
python schedule_identify.py  module_name elf_path ext_command good_sample bad_sample   
1. ImageMagick
``` 
python schedule_identify.py  libpng /usr/local/bin/magick  identify ./sample/png/good.png ./sample/png/bad.png
```
2. pngcheck
```
python schedule_identify.py pngcheck ./sample/png/origin_pngcheck/pngcheck " " ./sample/png/good.png ./sample/png/bad.png
```
# AFL Fuzz command
cd pintraces/sample/png  
AFL_INST_LIBS=1 afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@  
