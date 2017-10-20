from binascii import *
ll= "\x45\x00\x00\x54\x1a"



print crc32("hello world")
# Or, in two pieces:
crc = crc32("hello")
crc = crc32(" world", crc) 
print 'crc32 = 0x%08x' % crc