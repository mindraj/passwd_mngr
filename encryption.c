#include "passwords.h"

unsigned char *get_enc_key(void)
{
	static unsigned char key[crypto_secretstream_xchacha20poly1305_KEYBYTES];
	char *password = ask_info("Input password: ", "s", 0, NULL);

	// Make salt
	unsigned char salt[crypto_pwhash_SALTBYTES];
	int salt_fd;
	FILE *salt_file;
	if ((salt_fd = open("salt", O_RDONLY)) == -1) // No salt file present
	{
		// Make salt file
		randombytes_buf(salt, sizeof(salt));
		salt_file = fopen("salt", "wb");
		fwrite(salt, 1, sizeof(salt), salt_file);
		puts("Generated salt");
	}
	else 
	{
		// Read from salt file if it exist
		salt_file = fdopen(salt_fd, "rb");
		fread(salt, 1, sizeof(salt) , salt_file);
		puts("Have read salt");
	}

	// Derive key
	if (crypto_pwhash(key, sizeof(key),
	                  password, strlen(password), salt,
					  crypto_pwhash_OPSLIMIT_INTERACTIVE,
					  crypto_pwhash_MEMLIMIT_INTERACTIVE,
					  crypto_pwhash_ALG_DEFAULT) != 0)
	{
		puts("Key derivation failed");
		exit(EXIT_FAILURE);
	}
	sodium_memzero(password, strlen(password));
	free(password);

	return key;
}

void encrypt_passwd_file(FILE *passwd_file, char *passwd_filename, unsigned char *key)
{
	puts("Starting encryption");
	// Preparations
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	unsigned char input_buffer[2048];
	unsigned char output_buffer[2048 + crypto_secretstream_xchacha20poly1305_ABYTES];

	// Get name of temporary filename and open it as a string
	FILE *tmp_enc_file = tmpfile();
	if (tmp_enc_file == NULL)
	{
		puts("Failed to create a temporary encrypted file");
		exit(EXIT_FAILURE);
	}

	// Write the header
	crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
	fwrite(header, 1, sizeof(header), tmp_enc_file);

	int num_read;
	unsigned char tag = 0;
	for (bool success = false; success == false;)
	{
		puts("Started the encryption loop");
		num_read = fread(input_buffer, 1, sizeof(input_buffer), passwd_file);
		if (feof(passwd_file) != 0)
		{
			tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
			success = true;
			puts("EOF");
		}

		crypto_secretstream_xchacha20poly1305_push
			(&state, output_buffer, NULL,
			 input_buffer, num_read, NULL, 0, tag);

		fwrite(output_buffer, 1,
				(num_read + crypto_secretstream_xchacha20poly1305_ABYTES), 
				tmp_enc_file);
	}
	puts("Exited the encryption loop");

	// Write the ciphertext from temporary location to passwd file
	rewind(tmp_enc_file);
	rewind(passwd_file);

	while (!feof(tmp_enc_file))
	{
		num_read = fread(input_buffer, 1, sizeof(input_buffer), tmp_enc_file);
		fwrite(input_buffer, 1, num_read, passwd_file);
	}

}

FILE *decrypt_passwd_file(FILE *passwd_file, char *passwd_filename, unsigned char *key)
{
	puts("Starting decryption");
	// Preparations
	crypto_secretstream_xchacha20poly1305_state state;
	unsigned char header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	unsigned char input_buffer[2048 + crypto_secretstream_xchacha20poly1305_ABYTES];
	unsigned char output_buffer[2048];
	
	FILE *tmp_dec_file = tmpfile();
	if (tmp_dec_file == NULL)
	{
		puts("Failed to create a temporary decrypted file");
		exit(EXIT_FAILURE);
	}

	// Read header
	fread(header, 1, sizeof(header), passwd_file);
	if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0)
	{
		puts("Invalide header");
		exit(EXIT_FAILURE);
	}

	// Reading loop
	int num_read;
	unsigned char tag = 0;
	for (bool success = false; success == false;)
	{
		num_read = fread(input_buffer, 1, sizeof(input_buffer), passwd_file);
		if (feof(passwd_file) != 0)
		{
			success = true;
			puts("EOF");
		}
		
		if (crypto_secretstream_xchacha20poly1305_pull
				(&state, output_buffer, NULL, &tag,
				 input_buffer, num_read, NULL, 0) != 0)
		{
			puts("Invalid ciphertext");
			exit(EXIT_FAILURE);
		}

		if ((tag == crypto_secretstream_xchacha20poly1305_TAG_FINAL) && (success != true))
		{
			puts("Premature file end");
			exit(EXIT_FAILURE);
		}

		fwrite(output_buffer, 1, 
				(num_read - crypto_secretstream_xchacha20poly1305_ABYTES), tmp_dec_file);
		fwrite(output_buffer, 1, 
				(num_read - crypto_secretstream_xchacha20poly1305_ABYTES), stdout);
	}
	rewind(tmp_dec_file);
	unlink(passwd_filename);
	passwd_file = fopen(passwd_filename, "w");

	while (!feof(tmp_dec_file))
	{
		puts("writing");
		num_read = fread(input_buffer, 1, sizeof(input_buffer), tmp_dec_file);
		fwrite(input_buffer, 1, num_read, passwd_file);
	}

	return tmp_dec_file;
}



