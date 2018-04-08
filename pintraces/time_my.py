import sys
def main(argv):
    print len(argv)
    f1=open(argv[1],'r')
    #f2=open(argv[2],'w')
    result = list()
    line1=''
    my_min = 0
    result1= list()
    
    for line in f1.readlines():
        result.append(line)
    for my_min in range(0,60):
        for line in result:
            if(line.find('min,')!=-1 and line.find('sec:')!=-1):
                tmp_min=int(line[(line.find('hrs, ')+5):line.find(' min,')],10)
                tmp_sec=int(line[(line.find('min, ')+5):line.find(' sec:')],10)
                
                if(tmp_min==my_min and tmp_sec==0):
                    tmp_count=int(line[(line.find('sec: ')+5):-1],10)
                    print "tmp_min: %d"%tmp_min
                    
                    
                    print line
                    result1.append(tmp_count)

                    break

    for tmp in result1:
        print str(tmp)            
    f1.close()

if __name__ == "__main__":
   
        main(sys.argv)
