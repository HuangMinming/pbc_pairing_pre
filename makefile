.PHONY:all
all:pre
pre:pre.c
	gcc -o $@ $^ -g -I//usr/local/include/pbc -L/usr/local/lib -lpbc -lgmp

.PHONY:clean
clean:
	rm -fr pre