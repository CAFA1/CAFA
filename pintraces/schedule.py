import os
import subprocess
import binascii
import struct
import shutil
import sys
good = "/home/bap/workspace/bap-0.7/pintraces/good.txt"
bad = "/home/bap/workspace/bap-0.7/pintraces/bad.txt"
def _crc32( v):   
    return (binascii.crc32(v) & 0xffffffff) 
def make_samples():
    f1 = open("good.txt","w")
    crcfile = _crc32("a"*20)
    crcfilestr = struct.pack("<I",crcfile)
    f1.write("a"*20+crcfilestr)
    f1.close()
    f1 = open("bad.txt","w")
    crcfile = 0x5678
    crcfilestr = struct.pack("<I",crcfile)
    f1.write("a"*20+crcfilestr)
    f1.close()
def run_cmd(offsets1,offsets2,coverage,elfpath,filepath):
     
    filename = filepath.split("/")[-1]
    pin_cmd = "/home/bap/workspace/bap-0.7/pin/pin -t /home/bap/workspace/bap-0.7/pintraces/obj-ia32/gentrace.so -taint-offsets "+offsets1+" -taint-offsets "+offsets2+"  -o 1-1 -log-limit 10000 -ins-limit 1000000  -c "+coverage+" -taint-files "+filename+" --  "+elfpath+" "+filepath
    print "[*] Just about to run ", pin_cmd
    os.system(pin_cmd)
    
def get_jz():
    f1 = open("1-1-0logs.txt","r")
    result = list()
    for line in f1.readlines():
        if(line.find("[HIGH-TNT_JMP] PC ")!=-1):
            result.append(int(line[line.index("0x"):line.index(" count")],16))
         
    return result
def get_bbl():
    f1 = open("1-1-addrs.txt","r")
    result = dict()
    for line in f1.readlines():
        line1 = line.split()
        result[int(line1[0],16)] = int(line1[1],10)
         
    return result 
#make_samples()
def print_list(list1):
    for i in list1:
        print "0x%x" %(i)
def print_dict(dict1):
    for key,value in dict1.items():
        print 'key=',key,',value=',value
def cleandir():
    os.remove("1-1-0logs.txt")
    os.remove("1-1-addrs.txt")
def find_all_next(arr,item):
    return [arr[i+1] for i,a in enumerate(arr) if a==item]
def compare_run(offsets1,offsets2,coverage,elfpath):
    run_cmd(offsets1,offsets2,coverage,elfpath,good)
    jz_good_list = get_jz()
    bbl_good = get_bbl()
    #cleandir()
    run_cmd(offsets1,offsets2,coverage,elfpath,bad)
    bbl_bad = get_bbl()
    result_jz=set()
    for jz in jz_good_list:
        if(bbl_good[jz]!=bbl_bad[jz]):
            result_jz.add(jz)
    print "next_good:"
    #print_dict(bbl_good)
    print "next_bad:"
    #print_dict(bbl_bad)

    return result_jz
def main(argv=sys.argv):
    offsets1 = argv[1]
    offsets2 = argv[2]
    coverage = argv[3]
    elfpath = argv[4]
    result_jz=compare_run(offsets1,offsets2,coverage,elfpath)
    print "result"
    print_list(result_jz)

if __name__ == "__main__":
    main(sys.argv)




