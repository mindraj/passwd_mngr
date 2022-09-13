all:
	gcc -o passwords passwords.c passwd_mngr.h encryption.c -lsodium

dev:
	gcc -Wall -o passwords passwords.c passwd_mngr.h encryption.c -lsodium
