all: harness

harness: harness.c
	gcc -O0 -o harness harness.c

clean:
	rm -f harness
