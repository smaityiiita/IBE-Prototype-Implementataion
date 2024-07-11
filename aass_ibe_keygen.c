/* The objective of this program is to demonstarte the use of our IBE Keygen() function. First, we read the MSK (alpha) from an input file, also read an 'ID' from command-line argument
then generate the Private-Key by calling our Keygen() function. Finally, save the geneated Private-Key into an output file. */
#include "AASS_IBE_header.h"

int main(int argc, char **argv) {
	// Variable Declarations
	FILE * msk_file, * privt_key_file;
	char * ID;
	element_t alpha, private_key;
	
	// Initialize the PBC libraray global parameters
    	myPBC_Initialize();
    	
    	// Initialize all PBC element variables
    	element_init_Zr(alpha, global_params);
    	element_init_G1(private_key, global_params);
    	
	// Checks whther minimum 2 command line arguments have been given or not
	if(argc < 3){
		printf("Error: Please Enter Correct Execution Command %d !!!\n", argc);
		exit(1);
	}
	
	// Open the Input file containing the MSK & also Read the ID specified as command-line arguments
	msk_file = fopen(argv[1], "rb");
	if(msk_file == NULL){
    		printf("Error: Couldn't open spefified input file: %s\n", argv[1]);
    		exit(1);
    	}
    	
	ID = argv[2];
	
	// Create and Open an Output file 'private_key.bin'
	privt_key_file = fopen("private_key.bin", "wb");
	if(privt_key_file == NULL){
    		printf("Error: Couldn't create output file for Private_Key: \n");
    		exit(1);
    	}
    	
    	// Read the MSK (alpha) from the given input file
    	read_element_from_file(alpha, msk_file);
    	
    	// Call the 'Keygen()' function to generate the Private-Key from the given MSK and ID
    	ibe_keygen(private_key, alpha, ID);

	// Save the Private-Key in the 'private_key.bin' file 
    	save_element_to_file(private_key, privt_key_file);
    	
    	// Close and Clear Everything
    	fclose(msk_file);
    	fclose(privt_key_file);
    	element_clear(alpha);
    	element_clear(private_key);
    	pairing_clear(global_params);
	return 0;
}
