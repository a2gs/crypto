all: clean test

test:
	cc -o test test.c rijndael-alg-fst.c rijndael-api-fst.c -I. -g -Wall
	cc -o test2 test2.c rijndael-alg-fst.c rijndael-api-fst.c -I. -g -Wall

clean:
	-rm test test2 *.o core
