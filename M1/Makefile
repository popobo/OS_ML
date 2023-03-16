CC = gcc
LD = gcc

pstree: pstree.c
	$(CC) -Wall -o $@ $<

.PHONY: run

run: pstree
	./pstree -p -V -n