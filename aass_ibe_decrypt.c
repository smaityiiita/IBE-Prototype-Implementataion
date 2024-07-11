/* The objective of this program is to demonstarte the use of our IBE Decrypt() function. We first read the IBE Private-Key (D), the IBE Ciphertext (C1,C2) and the IBE-Params from specified input files.
We use our IBE Decrypt() function to decrypt the IBE Ciphertext using the IBE Private-Key. The decrypted item is actually an AES symmetric-key.
We use this symmetric-key to decrypt the given Ciphertext-Data file using AES decryption. 
The final output (decrypted data-file) will be saved as 'output.jpeg' .  */
#include "AASS_IBE_header.h"

int main(int argc, char **argv) {
	// Variable declarations
	FILE *cipher_file, *encrptd_key_file, *ibparams_file, *privt_key_file;
	element_t private_key, C1;
   	IBEPARAMS ibeparams;
   	unsigned char * C2, * decr_key;
	
	// Initialize the PBC libraray global parameters
    	myPBC_Initialize();
	
	// Intializing all PBC 'element_t' element variables
    	element_init_G1(private_key, global_params);
    	element_init_G2(C1, global_params);
	element_init_G2(ibeparams.g, global_params);
    	element_init_G2(ibeparams.g1, global_params);
    	
    	// All dynamic memory allocations
    	decr_key = malloc(EVP_MAX_KEY_LENGTH);
    	C2 = malloc(EVP_MAX_KEY_LENGTH);
    	
    	// Checks whether minimum 4 command line arguments have been given or not
	if(argc < 5){
		printf("Error: Please Enter Correct Execution Command %d !!!\n", argc);
		exit(1);
	}
	
	// Open the four Input files containing the Ciphertext-data, encrypted-symmetric-key, IBE-Params and the IBE Private-Key
	cipher_file = fopen(argv[1], "rb");
	if(cipher_file == NULL){
    		printf("Error: Couldn't open Specified Ciphertext File %s \n", argv[1]);
    		exit(1);
    	}
    	
    	encrptd_key_file = fopen(argv[2], "rb");
	if(encrptd_key_file == NULL){
    		printf("Error: Couldn't open Specified Encrypted-Key File %s \n", argv[2]);
    		exit(1);
    	}
    	
    	ibparams_file = fopen(argv[3], "rb");
	if(ibparams_file == NULL){
    		printf("Error: Couldn't open Specified IBE-Params File %s \n", argv[3]);
    		exit(1);
    	}
    	
    	privt_key_file = fopen(argv[4], "rb");
	if(privt_key_file == NULL){
    		printf("Error: Couldn't open Specified IBE-Priate-Ky File %s \n", argv[4]);
    		exit(1);
    	}
    	
    	// Read the IBE Private-key from file
    	read_element_from_file(private_key, privt_key_file);
    	
    	// Read the IBE Params from file
    	read_element_from_file(ibeparams.g, ibparams_file);
    	read_element_from_file(ibeparams.g1, ibparams_file);
    	
    	// Read the IBE Ciphertext(C1,C2) from file
    	read_element_from_file(C1, encrptd_key_file);
    	int retcode = fread(C2, 1, EVP_MAX_KEY_LENGTH, encrptd_key_file);
    	if(retcode == 0){
    		printf("Error while reading from encrptd_key_file!\n");
    		exit(1);
    	}
    	   	
    	// Deccrypt the IBE-Ciphertext(C1,C2) to get the symmetric key
    	ibe_decrypt(private_key, C1, C2, ibeparams, decr_key);
    	
    	// Use the symmetric key to decrypt the ciphertext data-file   -- output will be saved into 'output.jpeg'
	MyAES_128_ECB_Decr(cipher_file, decr_key);
	
	// Close and Clear Everything
	fclose(cipher_file);
	fclose(encrptd_key_file);
	fclose(ibparams_file);
	fclose(privt_key_file);
	element_clear(private_key);
	element_clear(C1);
	element_clear(ibeparams.g);
	element_clear(ibeparams.g1);
	pairing_clear(global_params);
	free(decr_key);
	free(C2);
	return 0;
}



