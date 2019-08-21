CC=clang -std=gnu99
CFLAGS= -pedantic -Wall -Wextra -O3 -march=native -g

.PHONY: all library static-library dynamic-library \
        check test vectors speed \
        clean

all: monokex.o

check: test
test: test.out
	./test.out
clean:
	rm -rf *.out *.o

monocypher.o: monocypher.c    monocypher.h
monokex.o   : monokex.c       monokex.h monocypher.h
test.o      : test.c utils.h monokex.h monocypher.h
monokex.o test.o: 
	$(CC) $(CFLAGS) -fPIC -c -o $@ $<

test.out   : test.o    monokex.o monocypher.o
test.out   : 
	$(CC) $(CFLAGS) -fPIC -o $@ $^
