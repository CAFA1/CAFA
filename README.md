# Note that there is the other branch (taint branch).   
The master branch is for software with the crc32 checksum algorithm, while the taint branch is for the general checksum algorithm.

# OS
Ubuntu 12.04 32bit (Other OS may have problems.)

# Install
```
git clone https://github.com/zhuceyongdela1234/taint_checksum.git  
git checkout master
cd pintraces  
make 
``` 

# Require and configure
echo core >/proc/sys/kernel/core_pattern  
echo 0 >/proc/sys/kernel/randomize_va_space  
Install the test software and afl-fuzz.  
Set  AFL_PATH to the root directory of afl-fuzz.  
   

# Commands to identify checksum points
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
1. Before patching  
```
cd pintraces/sample/png  
afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@  
```
2. After patching  
```
cd pintraces/sample/png  
cp ./libpng/patch/libpng12.so.0.46.0 /usr/local/lib/libpng12.so.0    
afl-fuzz -i in -o out -Q -- /usr/local/bin/magick identify @@  
```