/* The objective of this program is to demonstarte the use of our IBE Setup() function. The setup() function is called to generate the MSK and the IBE-params: g and g1, 
then the values are stored in output binary files. The MSK and the ibe-params are stored in two seperate files named 'MSK.bin' and 'ibeparams.bin' */

#include "AASS_IBE_header.h"

int main(int argc, char **argv) {
    // Variable Declarations
    FILE *msk_file, *ibparams_file;
    SETUPVALS setup_vals;
    
    // Initialize the PBC libraray global parameters
    myPBC_Initialize();
    
    // Create and Open Two Output files 'MSK.bin' and 'ibeparams.bin'
    msk_file = fopen("MSK.bin", "wb");
    if(msk_file == NULL){
    	printf("Error: Couldn't create MSK output file!\n");
    	exit(1);
    }
    
    ibparams_file = fopen("ibeparams.bin", "wb");
    if(ibparams_file == NULL){
    	printf("Error: Couldn't create ibeparams output file!\n");
    	exit(1);
    }
    
    // Call the 'setup' function to generate the setup phase outputs of IBE, viz., MSK and the ibeparams g and g1
    setup_vals = ibe_setup();
    
    // Save the MSK (alpha) in 'MSK.bin' file  and save the ibeparams g and g1 in 'ibeparams.bin' file
    save_element_to_file(setup_vals.alpha, msk_file);
    save_element_to_file(setup_vals.ibeparams.g, ibparams_file);
    save_element_to_file(setup_vals.ibeparams.g1, ibparams_file);
    
    // Close and Clear Everything
    fclose(msk_file);
    fclose(ibparams_file);
    element_clear(setup_vals.alpha);
    element_clear(setup_vals.ibeparams.g);
    element_clear(setup_vals.ibeparams.g1);
    pairing_clear(global_params);
    return 0;
}


