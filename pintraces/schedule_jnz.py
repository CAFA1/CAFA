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
    f1 = open("1-1-addrs.txt","r")
    result = list()
    for line in f1.readlines():
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
    os.system("cp 1-1-addrs.txt good_1.txt")
    run_cmd(offsets1,offsets2,coverage,elfpath,bad)
    os.system("cp 1-1-addrs.txt bad_2.txt")
    os.system("diff good_1.txt bad_2.txt > diff.txt")
    os.system("echo 1,1 >> diff.txt")
    f1 = open("diff.txt","r")
    #get seperate
    r_good=dict()
    r_bad = dict()
    tmp_good=list()
    tmp_bad=list()
    gang=0
    
    index = 0
    for line in f1.readlines():
        
        if(line.find("< ")!=-1 ): #good
            #print line
            tmp_good.append(line)
            #good[index] = 
        
        elif(line.find("> ")!=-1):
            tmp_bad.append(line)
        elif(line.find(",")!=-1):
            if len(tmp_good):
                r_good[index]=list(tmp_good)
                del tmp_good[:]
            else:
                r_good[index]=[]

            #print str(index)+" good:"
            #print r_good[index]
            if len(tmp_bad):
                r_bad[index]=list(tmp_bad)
                del tmp_bad[:]
            else:
                r_bad[index]=[]

            #print str(index)+" bad:"
            #print r_bad[index] 
            index=index+1
        else:
            pass

    len_cmp = len(r_good)
    result_jz=set()
    for i in range(len_cmp):
        if(len(r_good[i])!=0 and len(r_bad[i])!=0):
            result_good=dict()
            result_bad=dict()
            for line in r_good[i]:
                line1 = line.split()
                result_good[int(line1[1],16)] = int(line1[2],10)
            for line in r_bad[i]:
                line1 = line.split()
                result_bad[int(line1[1],16)] = int(line1[2],10)

            for jz in result_good:
                if(result_bad.has_key(jz) ):
                    if(result_good[jz]!=result_bad[jz]):
                        result_jz.add(jz)
    print_list(result_jz)
    #print_dict(r_good)
    #print_dict(r_bad)

    return #result_jz
def main(argv=sys.argv):
    offsets1 = argv[1]
    offsets2 = argv[2]
    coverage = argv[3]
    elfpath = argv[4]
    compare_run(offsets1,offsets2,coverage,elfpath)
    print "result"
    #print_list(result_jz)

if __name__ == "__main__":
    main(sys.argv)




