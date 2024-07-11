all: setup keygen verifykey encrypt decrypt

setup:
	@echo "Compiling the setup algo..."
	gcc -o aass_ibe_setup aass_ibe_setup.c  -lgmp -lpbc -lcrypto
	
keygen:
	@echo "Compiling the keygen algo..."
	gcc -o aass_ibe_keygen aass_ibe_keygen.c  -lgmp -lpbc -lcrypto
	
verifykey:
	@echo "Compiling the verify-key algo..."
	gcc -o aass_ibe_verifykey aass_ibe_verify_key.c -lgmp -lpbc -lcrypto
	
encrypt:
	@echo "Compiling the encrypt algo..."
	gcc -o aass_ibe_encrypt aass_ibe_encrypt.c -lgmp -lpbc -lcrypto

decrypt:
	@echo "Compiling the decrypt algo..."
	gcc -o aass_ibe_decrypt aass_ibe_decrypt.c -lgmp -lpbc -lcrypto
	
clean:
	@echo "Remove all executable and output files..."
	rm aass_ibe_setup aass_ibe_keygen aass_ibe_verifykey aass_ibe_encrypt aass_ibe_decrypt MSK.bin ibeparams.bin private_key.bin ciphertext.bin encrypted_key.bin output.jpeg
	

		
	

