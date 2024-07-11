/* The objective of this program is to demonstarte the use of our IBE Encrypt() function. First, we read the IBE Parameters from the specified input file and read an 'ID' from
command-line arguments. Next, we generate a random AES symmetric-key by calling appropriate OpenSSL function.
Then, we encrypt the specified data file with AES encrypion using the symmetric-key.
Finally, we encrypt the symmetric-key with IBE Encrypt() finction under the given ID and IBE params. 
The program generates two binary output files- one for the ciphertext of the data-file,
and the other contains the encrypted symmetric-key. */
#include "AASS_IBE_header.h"

int main(int argc, char **argv) {
	// Variable Declarations
	FILE * plaintext_file, * params_file; 
	unsigned char * ID;
	unsigned char symkey[EVP_MAX_KEY_LENGTH];
	IBEPARAMS ibeparams;
	
	// Initialize the PBC libraray global parameters
    	myPBC_Initialize();
    	
    	// Initialize all PBC element variables
    	element_init_G2(ibeparams.g, global_params);
    	element_init_G2(ibeparams.g1, global_params);
    	
	// Checks whether minimum 3 command line arguments have been given or not
	if(argc < 4){
		printf("Error: Please Enter Correct Execution Command %d !!!\n", argc);
		exit(1);
	}
	
	// Open the two Input files containing the Plaintext data, and containing the IBE-Params,  & also Read the ID specified as command-line arguments
	plaintext_file = fopen(argv[1], "rb");
	if(plaintext_file == NULL){
    		printf("Error: Couldn't open spefified input data-file: %s\n", argv[1]);
    		exit(1);
    	}
    	
    	params_file = fopen(argv[2], "rb");
	if(params_file == NULL){
    		printf("Error: Couldn't open spefified input params-file: %s\n", argv[2]);
    		exit(1);
    	}

	ID = argv[3];
	
    	// Read the IBE-Params from the specified input file
	read_element_from_file(ibeparams.g, params_file);
    	read_element_from_file(ibeparams.g1, params_file);
    	
    	// Generate a Random AES symmetric-key
    	if (!RAND_bytes(symkey, EVP_MAX_KEY_LENGTH)) 
    	 	handleErrors("Function: ibe-encrypt.c main");
	
	// Encrypt the data-file with the symmetric-key --- output will be stored in 'ciphertext.bin'
	MyAES_128_ECB_Encr(plaintext_file, symkey);
	
	// Encrypt the symmetric-key under the given ID and params --- output will be stored in 'encrypted_key.bin'
	ibe_encrypt(symkey, ID, ibeparams);
	
	// Close and Clear Everything
	fclose(plaintext_file);
	fclose(params_file);
	element_clear(ibeparams.g);
	element_clear(ibeparams.g1);
	pairing_clear(global_params);
	return 0;
}



