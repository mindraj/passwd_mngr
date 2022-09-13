#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdbool.h>
#include <sodium.h>
#include <unistd.h>

#define strip_trailing_nl(string) string[strlen(string) - 1] = '\0'
#define clear_input_buffer                                    \
		{                                                     \
			int cs;                                           \
			while ((cs = getchar()) != '\n' && cs != EOF) {}  \
		} 

extern void *ask_info (char *prompt, char *type, int length, int (*evaluation_function)(void *));

int encrypt_passwd_file(FILE * input_file, char *passwd_filename);

FILE *decrypt_passwd_file (FILE *input_file, char *passwd_filename);
