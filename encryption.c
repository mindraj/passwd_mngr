#include "passwd_mngr.h"

int encrypt_passwd_file(FILE * input_file, char *passwd_filename)
{

	// Values libsodium needs and temp file
	// to store encrypted file before overwriting cleartext
	crypto_secretstream_xchacha20poly1305_state state;
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	unsigned char  input_buf[2048];
    unsigned char  output_buf[2048 + crypto_secretstream_xchacha20poly1305_ABYTES];

	// Make temporary encrypted file
	FILE *temp_enc_pfile;
	char tmp_filename[] = "encrypted_passwd.tmpXXXXXX";
	temp_enc_pfile = fdopen(mkstemp(tmp_filename), "wb");
	
	// Obtain key from user
	unsigned char *key = get_enc_key();

	// Initialize libsodium
	crypto_secretstream_xchacha20poly1305_init_push(&state, header, key);
	free(key);
	fwrite(header, 1, sizeof(header), temp_enc_pfile);

	// Encrypt passwd file and store the encrypted file in temporary location
	int num_read;
	unsigned char tag = 0;
	int output_len;
	for (bool success = false; success == false;)
	{
		if (((num_read = fread(input_buf, 1, sizeof(input_buf), input_file)) != sizeof(input_buf) || (feof(input_file) != 0)))
		{
			tag = crypto_secretstream_xchacha20poly1305_TAG_FINAL;
			success = true;
		}

		 crypto_secretstream_xchacha20poly1305_push
			 (&state, output_buf, &output_len, input_buf, num_read, NULL, 0, tag);

		 fwrite(output_buf, 1, output_len, temp_enc_pfile);
	}
	
	// Delete the original, unecrypted passwd file
	unlink(passwd_filename);

	// Rename temporary file to become the new encrypted passwd file
	rename(tmp_filename, passwd_filename);

	return 0;
}

FILE *decrypt_passwd_file (FILE *input_file, char *passwd_filename)
{
	crypto_secretstream_xchacha20poly1305_state state;
    unsigned char  header[crypto_secretstream_xchacha20poly1305_HEADERBYTES];
	unsigned char  input_buf[2048];
    unsigned char  output_buf[2048 + crypto_secretstream_xchacha20poly1305_ABYTES];

	FILE *temp_dec_pfile = tmpfile();

	unsigned char *key = (unsigned char) ask_info("Input password: ", "s", 0, NULL);

	if (crypto_secretstream_xchacha20poly1305_init_pull(&state, header, key) != 0)
	{
		puts("Header is invalid");
		exit(EXIT_FAILURE);
	}
	
	int num_read;
	int output_len;
	unsigned char tag;
	for (bool success = false; success == false;)
	{
		if ((num_read = fread(input_buf, 1, sizeof(input_buf), input_file)) != sizeof(input_buf))
			success = true;

		if (crypto_secretstream_xchacha20poly1305_pull 
				(&state, output_buf, &output_len, &tag, input_buf, num_read, NULL, 0) != 0)
		{
			puts("Corrupted chunks");
			exit(EXIT_FAILURE);
		}

		 fwrite(output_buf, 1, output_len, temp_dec_pfile);
	}

	for (int ch; (ch = getc(temp_dec_pfile)) != EOF;)
		putchar(ch);
	putchar('\n');

	return temp_dec_pfile;
}
