/* sumator.h */
#ifndef CRYPTO_H
#define CRYPTO_H


#include "reference.h"
#include "io/sha256.h"
#include "io/aes256.h"
#include <openssl/hmac.h>

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>


class Crypto : public Reference {
    OBJ_TYPE(Crypto,Reference);

	private:
		unsigned char *keyToUse;
		
		bool use_hmac ;
		
		int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext);
  
		int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext);
  		
	protected:
		 static void _bind_methods();
		
	public:
		Crypto(){
			use_hmac = true;
		}
		
		void set_password(String password);
		void set_key(Vector<uint8_t> key);
		
		void set_HMAC(bool hmac);
		
		Vector<uint8_t> encrypt_string( String plainText);
		Vector<uint8_t> encrypt_raw( Vector<uint8_t> plainRaw);
		
		String decrypt_string (Vector<uint8_t> encrypted);	
		Vector<uint8_t> decrypt_raw (Vector<uint8_t> encrypted);
				
		Vector<uint8_t>  create_HMAC(Vector<uint8_t> data);
};

#endif

