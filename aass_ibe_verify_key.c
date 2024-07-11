/* The objective of this program is to demonstarte the use of our IBE Verifykey() function. First, we read an IBE Private-Key (D) and IBE-Params (g, g1) from two input files, 
we also read an 'ID' from command-line argument.
Finally, we call the Verifykey() function to check whether the given Private-Key matches with the given ID under the given IBE Parameters or not. */
#include "AASS_IBE_header.h"

int main(int argc, char **argv) {
	// Variable Declarations
	FILE * ibparams_file, * privt_key_file;
	char * ID;
	element_t private_key;
	IBEPARAMS ibeparams;
	
	// Initialize the PBC libraray global parameters
    	myPBC_Initialize();
	
	// Initialize all PBC element variables
	element_init_G1(private_key, global_params);
    	element_init_G2(ibeparams.g, global_params);
    	element_init_G2(ibeparams.g1, global_params);
    	
	// Checks whther minimum 3 command line arguments have been given or not
	if(argc < 4){
		printf("Error: Please Enter Correct Execution Command %d !!!\n", argc);
		exit(1);
	}
	
	// Open the Input files containing the IBE-Params and the Private-Key, & also Read the ID specified as command-line arguments
	ibparams_file = fopen(argv[1], "rb");
	if(ibparams_file == NULL){
    		printf("Error: Couldn't open spefified input file: %s\n", argv[1]);
    		exit(1);
    	}
	
	privt_key_file = fopen(argv[2], "rb");
	if(privt_key_file == NULL){
    		printf("Error: Couldn't open spefified input file: %s\n", argv[2]);
    		exit(1);
    	}
    	
	ID = argv[3];
    	
    	// Read the Private-Key and the IBE-Params from the specified input files
    	read_element_from_file(private_key, privt_key_file);
    	read_element_from_file(ibeparams.g, ibparams_file);
    	read_element_from_file(ibeparams.g1, ibparams_file);
    	
    	// Call our Verifykey() function to chcek whether the Private-Key matches with the given ID, under the given IBE-params or not
	if( ibe_verify_key(private_key, ID, ibeparams)){
		printf("Private-key Matches with the Given ID against the Given IBE Params. \n");
	}
	else{
		printf("!!! Private-key Does-Not with the Given ID against the Given IBE Params.!!! \n");
	}
	
	// Close and Clear Everything
	fclose(ibparams_file);
	fclose(privt_key_file);
	element_clear(private_key);
	element_clear(ibeparams.g);
	element_clear(ibeparams.g1);
	pairing_clear(global_params);
	return 0;
}
