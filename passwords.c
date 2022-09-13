#include "passwords.h"

#if defined(__linux__) || defined(__FreeBSD__) || defined(__CYGWIN__)
char *make_passwd(int passwd_length)
{
	FILE *random = fopen("/dev/urandom", "r");
	char *passwd = malloc(passwd_length);
	unsigned char random_byte = 0;
	for (int i = 0; i < passwd_length;)
	{
		random_byte = (unsigned char) getc(random);
		if (isalnum(random_byte))
		{
			passwd[i] = random_byte;
			i++;
		}
	}
	fclose(random);
	return passwd;
}
#else
	#error Not a supported platform.
#endif

char *find_passwd(char *identity, FILE *passwd_file)
{
	char *saved_name = malloc(strlen(identity));
	char *passwd = malloc(50);
	
	// Find
	for (;;)
	{
		int ch;
		// Clear saved name
		memset(saved_name, '\0', strlen(identity));

		// Peek to check that next up isn't EOF
		if ((ch = fgetc(passwd_file)) == EOF)
		{
			return NULL;
		}
		else
		{
			ungetc(ch, passwd_file);
		}

		// Save the identity name to a string
		for (int i = 0;; i++)
		{
			ch = fgetc(passwd_file);
			if ((ch == '\t') || (i > strlen(identity)))
				break;

			saved_name[i] = ch;
		}
		
		// If found matching identity name - break
		if (strcmp(saved_name, identity) == 0)
			break;

		// Skip to the next line
		while (fgetc(passwd_file) != '\n') {}

	}
	free(saved_name);

	// Read password string
	for (int i = 0, ch; (ch = fgetc(passwd_file)) != '\n'; i++)
	{
		if (i == 50)
			passwd = realloc(passwd, i + 50);

		passwd[i] = ch;
	}
	
	// Very important to rewind, otherwise subsequent operations
	// with the file will fail.
	rewind(passwd_file);

	puts("find_passwd returned");
	return passwd;
}

void *ask_info(char *prompt, char *type, int length, int (*evaluation_function)(void *))
{
	/* Generic ask the user function
	 *
	 * Prompt will be displayed before
	 * the input field.
	 *
	 * Supports the following types:
	 * "i" - long int
	 * "s" - char *
	 *
	 * For integers lenth argument is ingored.
	 * Strings will be saved up to specified lenth, 
	 * or dynamically allocated to any size if
	 * lenth is set to 0.
	 *
	 * Evaluation function is there when you need
	 * to discard certain types of input.
	 * The input collected by this fuction is passed to
	 * evaluation function before being returned.
	 * If evaluation function function returns 0,
	 * the input is discarded and NULL is returned by 
	 * this function otherwise if any non-0 value is returned
	 * the function returns pointer to the value gethered from the user
	 *
	 * Pass NULL as evaluation_function if you do not
	 * need this functionality.
	 */

	void *result;
	bool success = false;

	fputs(prompt, stdout);
	if (strcmp(type, "i") == 0)
	{
		char *number_string = malloc(10);
		memset(number_string, '\0', 10);

		result = malloc(sizeof(long int));
		
		while (success == false)
		{
			int ch;

			if (strlen(number_string) == 10)
			{
				number_string = realloc(number_string, (strlen(number_string) + 10));
			}

			ch = getchar();
			if (ch == '\\')
			{
				if (getchar() == 'q')
				{
					exit(EXIT_SUCCESS);
				}
				else
				{
					printf("\n%s", prompt);
					clear_input_buffer;
				}
			}
			else if (ch == '\n' || ch == EOF)
			{
				success = true;
				number_string[strlen(number_string)] = '\0';
			}
			else if (isdigit(ch) == 0)
			{
				printf("\n%s", prompt);
				clear_input_buffer;
			}
			else 
			{
				number_string[strlen(number_string)] = ch;
			}
		}

		*(long int *) result = atoi(number_string);
	}
	else if (strcmp(type, "s") == 0) 
	{
		// Declare pointer to string local to the function
		// and allocate memory. That is needed because
		// the result variable is a void pointer 
		// and you can't perform the usual array subscripting on them.

		char *flocal_result = malloc(50);
		int ch;

		// Collect characters until
		// success flag is set to true
		for (int i = 0; success == false; i++)
		{
			// If not enough allocated memory, realloc more
			if (i == 50)
				flocal_result = realloc(flocal_result, i + 50);

			// Get character
			ch = getchar();

			// If reached newline or EOF
			// set success to true, exit the for loop
			if (ch == '\n' || ch == EOF)
			{
				// Append newline at the end because C strings
				flocal_result[i] = '\0';
				success = true;
			}
			// If '\' appears, check
			// it isn't part of "\q" quit expression
			else if (ch == '\\')
			{
				flocal_result[i] = ch;
				ch = getchar();
				// If it is, quit
				if (ch == 'q')
					exit(EXIT_SUCCESS);
				else if (ch == '\n' || ch == EOF)
					// If it's EOF or newline, end the loop
					success = true;
				else
					// If it isn't sotre and coninue
					flocal_result[++i] = ch;
			}
			// So tabs are used as the delimeter in the .passwd file
			// hence they're prohibited in user input.
			// Displays a warning and asks again using recursion
			else if (ch == '\t')
			{
				puts("Tabs are not permitted in the identifiers");
				clear_input_buffer;
				flocal_result = ask_info(prompt, type, length, evaluation_function);
				success = true;
			}
			else
			{
				flocal_result[i] = ch;
			}

			// Do something with length argument or nothing if it's 0
			if (length == 0)
				;
			else 
			{
				if (i == length)
					success = true;
			}
		}
		// Store result local to the function to 
		// result that will be returned. (to a void pointer)
		result = flocal_result;
	}

	if (evaluation_function == NULL)
	{
		return result;
	}
	else 
		return (evaluation_function(result) == 0 ? NULL : result);
}


void append_passwd_file(FILE *passwd_file)
{

	// Declare variables
	long int *passwd_length;
	char *identity;
	
	// Get identity name
	for (;;)
	{
		identity = ask_info("Identity name? ", "s", 0, NULL);
		if (find_passwd(identity, passwd_file) == NULL)
		{
			break;
		}
		else
		{
			puts("\nPassword for identity already present\n");
			free(identity);
		}
	}
	
	// Generate password
	
	// Ask for password length until password lenth is obtained
	passwd_length = 
		ask_info("How long should the password be? ", "i", 0, NULL);
		
	char *passwd = make_passwd(*passwd_length);

	// Put everything into the file
	// and password in stdout
	fprintf(passwd_file, "%s\t%s\n", identity, passwd);
	printf("The password for %s is\n\n%s\n\n", identity, passwd);

	exit(EXIT_SUCCESS);
}

void query_passwd_file(FILE *passwd_file)
{
	
	// Get identity name
	char *identity = ask_info("Identity name? ", "s", 0, NULL);

	// Find password or fail
	char *passwd = find_passwd(identity, passwd_file);
	if (passwd == NULL)
	{
		fprintf(stderr, "\nIdentity not found!\n\n");
		exit(EXIT_FAILURE);
	}

	// Print
	printf("Password for %s:\n\n%s\n\n", identity, passwd);
	
	exit(EXIT_SUCCESS);
}


int main(void)
{
	// Greeting
	puts("Welcome to Mindraj's Password Management Wizzard (MiPMM)!\n"
			"Enter \\q to any prompt to quit\n");

	bool success = false;
	bool creating_new = false;

	// Init libosodium or fail
	if (sodium_init() < 0) 
	{
		puts("Initializing sodium failed!");
		exit(EXIT_FAILURE);
	}
	unsigned char *key = get_enc_key;

	// Ask service
	char *service;
	service = ask_info("What service? ", "s", 0, NULL);

	// Make filename
	char *passwd_file_name = malloc(strlen(service) + strlen(".passwd\0"));
	sprintf(passwd_file_name, "%s.passwd", service);	

	// Scan folder for passwd files
#if defined(__linux__) || defined(__FreeBSD__) || defined(__CYGWIN__)

	DIR *program_directory;
	struct dirent *dirfile;
	bool found_passwd = false;

	program_directory = opendir("./");

	while ((dirfile = readdir(program_directory)) != NULL)
	{
		if (strcmp(dirfile->d_name, passwd_file_name) == 0)
		{
			found_passwd = true;
			break;
		}
	}
#else
#error Not a supported platform.
#endif

	if (!found_passwd)
	{

		char answer[5];
			
		for (;;)
		{
			printf("Service %s not found. Add it? (yes/no) ",
					service);

			fgets(answer, 5, stdin);
			strip_trailing_nl(answer);

			if (strcmp(answer, "no") == 0 || strcmp(answer, "\\q") == 0)
				exit(EXIT_SUCCESS);
			else if (strcmp(answer, "yes") == 0)
				break;
			else
				;
		}
		append_passwd_file(fopen(passwd_file_name, "a+"));
	}
	else
	{
		// Ask operation
		char *operation;
		for (bool success = false; success == false;)
		{
			operation = ask_info("(r)ead or (w)rite? ", "s", 10, NULL);
			success = true;
			
			if((strcmp(operation, "r") == 0) || (strcmp(operation, "read") == 0))
				query_passwd_file(fopen(passwd_file_name, "r"));
			else if((strcmp(operation, "w") == 0) || (strcmp(operation, "write") == 0))
				append_passwd_file(fopen(passwd_file_name, "a+"));
			else if(strcmp(operation, "\\q") == 0)
				exit(EXIT_SUCCESS);
			else if(strcmp(operation, "e") == 0)
				encrypt_passwd_file(fopen(passwd_file_name, "rb"), passwd_file_name);
			else if(strcmp(operation, "d") == 0)
				decrypt_passwd_file(fopen(passwd_file_name, "rb"), passwd_file_name);
			else
			{
				puts("Not a valid operation");
				success = false;
			}
		}
	}
}

