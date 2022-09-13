all:
	gcc -o passwords passwords.c passwords.h encryption.c -lsodium

dev:
	gcc -Wall -o passwords passwords.c passwords.h encryption.c -lsodium
