#include "passwords.h"

unsigned char *get_enc_key(void)
{
	static unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	unsigned char *password = ask_info("Input password: ", "s", 0, NULL);

	// Make salt
	unsigned char salt[crypto_pwhash_SALTBYTES];
	int salt_fd;
	FILE *salt_file;
	if ((salt_fd = open("salt", O_RDONLY)) == -1) // No salt file present
	{
		// Make salt file
		randombytes_buf(salt, crypto_pwhash_SALTBYTES);
		salt_file = fopen("salt", "wb");
		fwrite(salt, 1, crypto_pwhash_SALTBYTES, salt_file);
	}
	else 
	{
		// Read from salt file if it exist
		salt_file = fdopen(salt_fd, "rb");
		fread(salt, 1, crypto_pwhash_SALTBYTES, salt_file);
	}

	// Derive key
	if (crypto_pwhash(key, crypto_secretstream_xchacha20poly1305_KEYBYTES,
	                  password, strlen(password), salt,
					  crypto_pwhash_OPSLIMIT_INTERACTIVE,
					  crypto_pwhash_MEMLIMIT_INTERACTIVE,
					  crypto_pwhash_ALG_DEFAULT) != 0);
	{
		puts("Key derivation failed");
		exit(EXIT_FAILURE);
	}

	return key;
}
