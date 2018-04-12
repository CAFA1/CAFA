#patch binary scipt
# Firstly, you need to download the capstone source. Secondely, cd the root directory, make and make install. Thirdly, cd bindings/python, make and make install.
from capstone import *
import sys



def main(argv=sys.argv):
    file_name = argv[1]
    checksum_point = int(argv[2],16)
    file_r=open(file_name,'r')
    file_w=open(file_name+'.patch','w')
    file_str=file_r.read()
    #file_bytes=list(file_str)
    checksum_ins_str=file_str[checksum_point:checksum_point+10]
    conditional_mn = checksum_ins_str[0]
    conditional_mn1 = checksum_ins_str[1]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(checksum_ins_str, 0x1000):
        print("Before patching\t0x%x:\t%s\t%s" %(checksum_point, i.mnemonic, i.op_str))
        break
    if (conditional_mn=='\x74'): #je(jz) rel8
        conditional_mn='\x75' #jne(jnz) rel8
    elif (conditional_mn=='\x75'):
        conditional_mn='\x74'
    elif (conditional_mn=='\x0f' and conditional_mn1=='\x84'): #jz(je) rel16(rel32)
        conditional_mn1='\x85' #jnz(jne) rel16(rel32)
    elif (conditional_mn=='\x0f' and conditional_mn1=='\x85'): 
        conditional_mn1='\x84'   
    else:
        print 'error'
        exit()
    #print conditional_mn
    if(conditional_mn!='\x0f'):
        new_file_str=file_str[0:checksum_point]+conditional_mn+file_str[checksum_point+1:]
    else:
        new_file_str=file_str[0:checksum_point]+conditional_mn+conditional_mn1+file_str[checksum_point+2:]
    file_w.write(new_file_str)
    file_r.close()
    file_w.close()
    file_w=open(file_name+'.patch','r')
    file_str=file_w.read()
    checksum_ins_str=file_str[checksum_point:checksum_point+10]
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    for i in md.disasm(checksum_ins_str, 0x1000):
        print("After patching\t0x%x:\t%s\t%s" %(checksum_point, i.mnemonic, i.op_str))
        break
    file_w.close()

if __name__ == "__main__":
    print '''
    python patch_checksum.py file_name checksum_point
    e.g. python patch_checksum.py patch_sample/libpng/libpng12.so.0.46.0 0x7972
    '''
    
    if(len(sys.argv)!=3):
        print '''
        python patch_checksum.py file_name checksum_point
        '''
    else:
        main(sys.argv)