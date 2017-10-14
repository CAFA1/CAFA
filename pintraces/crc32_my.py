from binascii import *
ll= "\x0d\x4a\x11\x85"
ll2= "\x85\x11\x4a\x0d"
print "0x%08x" %crc32("hello world")
print "0x%08x" %crc32("hello world")
print "0x%08x" %crc32("hello world"+"hello world")
print "0x%08x" %crc32("hello world"+ll2)

print crc32("hello world")
# Or, in two pieces:
crc = crc32("hello")
crc = crc32(" world", crc) 
print 'crc32 = 0x%08x' % crc