/home/bap/workspace/bap-0.7/pin/pin -t /home/bap/workspace/bap-0.7/pintraces/obj-ia32/gentrace.so -taint-offsets 1 -taint-offsets 30  -o 1-1 -log-limit 10000 -ins-limit 1000000 -time-limit 35  -c magick -check 10 -taint-files good.png --  /usr/local/bin/magick identify /home/bap/workspace/bap-0.7/pintraces/sample/png/good.png


/home/bap/workspace/bap-0.7/pin/pin -t /home/bap/workspace/bap-0.7/pintraces/obj-ia32/gentrace.so -taint-offsets 1 -taint-offsets 30  -o 1-1 -log-limit 10000 -ins-limit 1000000 -time-limit 35  -c magick -check 10 -taint-files bad.png --  /usr/local/bin/magick identify /home/bap/workspace/bap-0.7/pintraces/sample/png/bad.png
