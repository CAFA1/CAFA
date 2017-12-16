import os
import subprocess
import binascii
import struct
import shutil
import sys


def run_cmd(offsets1,offsets2,coverage,elfpath,filepath,ext_command):
     
    filename = filepath.split("/")[-1]
    pin_cmd = "/home/bap/workspace/bap-0.7/pin/pin -t /home/bap/workspace/bap-0.7/pintraces/obj-ia32/gentrace.so -taint-offsets "+offsets1+" -taint-offsets "+offsets2+"  -o 1-1 -log-limit 10000 -ins-limit 1000000 -time-limit 35  -c "+coverage+" -taint-files "+filename+" --  "+elfpath+" "+ext_command+" "+filepath
    print "[*] Just about to run ", pin_cmd  #-skip-taints 2
    os.system(pin_cmd)
    
def get_high():
    f1 = open("1-1-0logs.txt","r")
    result = list()
    for line in f1.readlines():
        if(line.find("[HIGH-TNT_JMP] PC ")!=-1):
            result.append(int(line[line.index("0x"):],16))
    f1.close()   
    return result
def get_base():
    f1 = open("1-1-0logs.txt","r")
    
    for line in f1.readlines():
        if(line.find("lowaddr: ")!=-1):
            lowaddr=(int(line[line.index("0x"):line.index(" highaddr:")],16))
            highaddr=(int(line[line.index("highaddr: 0x")+len("highaddr: 0x"):],16))
            #print hex(lowaddr)
            #print hex(highaddr)
    f1.close()       
    return lowaddr,highaddr
def get_bbl():
    f1 = open("1-1-addrs.txt","r")
    result = dict()
    for line in f1.readlines():
        line1 = line.split()
        result[int(line1[0],16)] = int(line1[1],10)
    f1.close()     
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
def compare_run(offsets1,offsets2,coverage,elfpath,ext_command,good_sample,bad_sample):
    os.system("rm 1.txt")
    run_cmd(offsets1,offsets2,coverage,elfpath,good_sample,ext_command)
    os.system("cp 1-1-addrs.txt good_1.txt")
    os.system("rm 1.txt")
    run_cmd(offsets1,offsets2,coverage,elfpath,bad_sample,ext_command)
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
    result_jz=list()
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
                        result_jz.append(jz)
    print "result taint jnz(SET4)"
    myset=set()
    if(len(result_jz)):
        result_jz.sort()
        myset = set(result_jz)
        for item in myset:
            print("the %x has found %d" %(item,result_jz.count(item)))
    result_high=get_high()
    myset1 = set(result_high)
    print "|SET1| = %d" % len(myset1)
    print "|SET4| = %d" % len(myset)
    if(len(myset1)):
        result_all=myset1&myset
    else:
        result_all=myset
    print "result (high taint jnz)&(tiant jnz)"
    print_list(result_all)
    print "result between range"
    lowaddr,highaddr=get_base()
    result_relative=set()
    for tmp in result_all:
        if(tmp>lowaddr and tmp<highaddr):
            print hex(tmp)
            result_relative.add(tmp)
    print "result relative address of checksum"
    for tmp in result_relative:
        print hex(tmp-lowaddr)
    return #result_jz
def main(argv=sys.argv):
    offsets1 = argv[1]
    offsets2 = argv[2]
    coverage = argv[3]
    elfpath = argv[4]
    ext_command = argv[5]
    good_sample = argv[6]
    bad_sample = argv[7]
    # for gz test 
    # change based on your own directory
    os.system("rm ~/workspace/bap-0.7/pintraces/sample/gz/good.txt")
    os.system("cp ~/workspace/bap-0.7/pintraces/sample/png/*.png ~/workspace/bap-0.7/pintraces/sample/png/bak/")
    os.system("cp ~/workspace/bap-0.7/pintraces/sample/gz/bak/* ~/workspace/bap-0.7/pintraces/sample/gz/")
    compare_run(offsets1,offsets2,coverage,elfpath,ext_command,good_sample,bad_sample)
    
    

if __name__ == "__main__":
    
    print '''
    python schedule_identify.py taint_start taint_length module_name elf_path ext_command good_sample bad_sample
    taint_start: the starting offset of the taint source.
    taint_length: the length of the taint source.
    module_name: the name of the module where the checksum check is located.
    elf_path: the path of the test program.
    ext_command: the options of the test program.
    good_sample: the path of the well-formed sample.
    bad_sample: the path of the malformed sample.
    '''
    print len(sys.argv)
    if(len(sys.argv)!=8):
        print '''
        python schedule_identify.py taint_start taint_length module_name elf_path ext_command good_sample bad_sample
        taint_start: the starting offset of the taint source.
        taint_length: the length of the taint source.
        module_name: the name of the module where the checksum check is located.
        elf_path: the path of the test program.
        ext_command: the options of the test program.
        good_sample: the path of the well-formed sample.
        bad_sample: the path of the malformed sample.
        '''
    else:
        main(sys.argv)




