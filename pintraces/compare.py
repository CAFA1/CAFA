import os
f1=open("1-1-addrs.txt","r")
f2=open("11.txt","r")
f3=open("compare.txt","w")
lines = f1.readlines()
for line in lines:
    line2 = f2.readline()
    f3.write((line+" "+line2).strip('\n')+"\n")
f3.close()