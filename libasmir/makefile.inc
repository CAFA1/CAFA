VEX_DIR=/home/bap/workspace/bap-0.7/VEX
LIBASMIR_CXXFLAGS=-I/home/bap/workspace/bap-0.7/VEX/pub -I/home/bap/workspace/bap-0.7/src/include -g -O2
LIBASMIR_LDFLAGS=-L/home/bap/workspace/bap-0.7/VEX -L/home/bap/workspace/bap-0.7/src 
LIBASMIR_LIBS=-lasmir -lvex -lbfd -ldl -liberty -lz
CLIBS=asmir vex opcodes bfd z iberty stdc++
