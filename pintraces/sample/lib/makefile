so:main libhello.so
libhello.so:hello.h hello.c
	#gcc -o libhello.o -c hello.c -I. 
	gcc -shared -fPIC -o libhello.so hello.c  -lz
main:main.c libhello.so hello.h
	gcc  -L. -I.   -o main main.c -lhello

test:
	./main ./good.txt
	./main ./bad.txt
test_fuzz:
	afl-fuzz -i in -o out -Q -- ./main @@
clean:
	rm *.o *.so