#include "crypto.h"
#include <stdlib.h>
#include <iostream>

void Crypto::set_HMAC(bool hmac){
	use_hmac = hmac;
}

Vector<uint8_t> Crypto::create_HMAC(Vector<uint8_t> data){
			
	Vector<uint8_t> hashVec;
		
	hashVec.resize(32);
	
	
	//char key[] = "012345678";

    // The data that we're going to hash using HMAC
    //char hashStr[] = "hello world";
	
					
	unsigned char* result = HMAC(EVP_sha256(), keyToUse, 32 , data.ptr(), data.size(), NULL, NULL);    
		
	//unsigned char* result = HMAC(EVP_sha256(), key, strlen(key) , (unsigned char*)hashStr, strlen(hashStr), NULL, NULL);   
	
	
	for(size_t i=0;i<32;i++){
		hashVec[i] = result[i];
	}
	
	
	
	return hashVec;
	
	
}

void Crypto::set_password(String password){
	CharString cs=password.utf8();
	unsigned char key[32];
	sha256_context ctx;
	sha256_init(&ctx);
	sha256_hash(&ctx,(unsigned char*)cs.ptr(),cs.length());
	sha256_done(&ctx, key);
	
	Vector<uint8_t> keyVect;
	keyVect.resize(32);
	
	for(int i=0;i<32;i++){
		keyVect[i] = key[i];
	}

	Crypto::set_key(keyVect);	
}

void Crypto::set_key(Vector<uint8_t> key){
		
	if(key.size() < 32){
	
		size_t keySize = key.size();
	
		key.resize(32);
		
		for(size_t i =keySize; i<32; i++){
			key[i] = 0;
		}
		
	}else if(key.size() > 32){
		static unsigned char hash[32];
		
		Vector<uint8_t> data;
		
		sha256_context shaCtx;
		sha256_init(&shaCtx);
		sha256_hash(&shaCtx,(unsigned char*)data.ptr(),data.size());
		sha256_done(&shaCtx, hash);
				
		key.resize(32);
		
		for(size_t i=0;i<32;i++){
			key[i] = hash[i];
		}
	
	}
		
	
	keyToUse = new unsigned char[32];
	memcpy(keyToUse, key.ptr(), 32);

	//keyToUse = "12345678901234567890123456789012";
	
}

Vector<uint8_t> Crypto::encrypt_string(String plainText){
	

	CharString cs =  plainText.utf8();
	
	Vector<uint8_t> data;
	data.resize(cs.size());
	
	for(int i=0;i<cs.size();i++){
		data[i] = cs[i];
	}
	

	return encrypt_raw(data);
}

int Crypto::encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int ciphertext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

  /* Initialise the encryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    return -1;

  /* Provide the message to be encrypted, and obtain the encrypted output.
   * EVP_EncryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    return -1;
  ciphertext_len = len;

  /* Finalise the encryption. Further ciphertext bytes may be written at
   * this stage.
   */
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
  ciphertext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}
int Crypto::decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;

  int len;

  int plaintext_len;

  /* Create and initialise the context */
  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

  /* Initialise the decryption operation. IMPORTANT - ensure you use a key
   * and IV size appropriate for your cipher
   * In this example we are using 256 bit AES (i.e. a 256 bit key). The
   * IV size for *most* modes is the same as the block size. For AES this
   * is 128 bits */
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
    return -1;

  /* Provide the message to be decrypted, and obtain the plaintext output.
   * EVP_DecryptUpdate can be called multiple times if necessary
   */
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    return -1;
  plaintext_len = len;

  /* Finalise the decryption. Further plaintext bytes may be written at
   * this stage.
   */
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
	return -1;
  }
  
  plaintext_len += len;

  /* Clean up */
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

Vector<uint8_t> Crypto::encrypt_raw(Vector<uint8_t> plainRaw){
		
	Vector<uint8_t> data;
	
	aes256_context ctx;
	
	aes256_init(&ctx,keyToUse);
	
	
	int len = plainRaw.size();
	int paddedLen = len+ 1; //We need at least one byte to say how much padding their is.
	
	if (paddedLen % 16 > 0) {
		paddedLen+=16-(paddedLen % 16); //We need to get a 16byte block
	}
	
	
	unsigned char* ciphertext= new unsigned char[paddedLen+16];
		
	data.resize(16); 
						
	for(size_t j=0;j<16;j++){	
		data[j] = rand()%256; //random byte for the first 16.
	}
		
	aes256_encrypt_ecb(&ctx,&data[0]); //Now we encrypt the first 16 bytes to get our iv.
		
	aes256_done(&ctx);	
	
	unsigned char *iv = data.ptr();
	
	int ciphertext_len = encrypt (plainRaw.ptr(), len, keyToUse, iv, ciphertext);
		
	
	
	
	Vector<uint8_t> hash;
	
	if (use_hmac ){
	
		data.resize(ciphertext_len+16);
	
		for(size_t i =0; i < ciphertext_len;i++){
			data[i+16] = ciphertext[i]; //Add ciphertext after iv
		}
		
	
		hash = create_HMAC(data);
	
		data.resize(ciphertext_len+48);
		
		for(size_t i =ciphertext_len+47; i>=32 ;i--){
			data[i] = data[i-32]; //Make space for hash			
		}
		
		for(size_t i =0; i< 32;i++){
			data[i] = hash[i]; //Add the hash			
		}
	
	
	}else{
		data.resize(ciphertext_len+16);
		
		for(size_t i =0; i< ciphertext_len;i++){
			data[i+16] = ciphertext[i]; //Place the data after the iv
		}
	}
	
	
		
	return data;
}

String Crypto::decrypt_string (Vector<uint8_t> encrypted){
	Vector<uint8_t>  dc = decrypt_raw(encrypted);
	
	char* data = new char[dc.size()];
	
	for (size_t i =0;i<dc.size();i++){
		data[i] = (char)dc[i];
	}
	
	return String::utf8(data,dc.size());
}

Vector<uint8_t> Crypto::decrypt_raw (Vector<uint8_t> encrypted){
	
	
	Vector<uint8_t> iv;	iv.resize(16);
	Vector<uint8_t> msg;
	
	Vector<uint8_t> ReturnData;
	
	if (use_hmac){
		Vector<uint8_t> hash; 			hash.resize(32);
		Vector<uint8_t> msgToCheck;		msgToCheck.resize(encrypted.size()-32);
		
		for(size_t i =0; i<32; i++){
			hash[i] = encrypted[i];
		}
		
		for(size_t i=0;i<encrypted.size()-32; i++){
			msgToCheck[i] = encrypted[i+32];
		}
		
		Vector<uint8_t> calcHash = create_HMAC(msgToCheck);
		
		bool isCorrect = true;
		
		for(size_t i =0; i<32; i++){
			if (hash[i] != calcHash[i]){
				isCorrect = false;
			}
		}
		
		if(!isCorrect){
			return ReturnData;
		}
		
		msg.resize(msgToCheck.size()-16);
		
		for(size_t i=0;i<16; i++){
			iv[i] = msgToCheck[i];
		}
		
		
		for(size_t i=16;i<msgToCheck.size(); i++){
			msg[i-16] = msgToCheck[i];
		}
		
	}else{
		msg.resize(encrypted.size()-16);
		
		for(size_t i=0;i<16; i++){
			iv[i] = encrypted[i];
		}
		
		for(size_t i=16;i<encrypted.size(); i++){
			msg[i-16] = encrypted[i];
		}
			
		
	}
	
	unsigned char* plaintext= new unsigned char[msg.size()];
	
	int plaintext_len = decrypt(msg.ptr(), msg.size(), keyToUse,  iv.ptr(), plaintext);
  
	ReturnData.resize(plaintext_len);
	
	for(size_t i =0;i < plaintext_len; i++){
		ReturnData[i] = plaintext[i];
	}
		
	return ReturnData;
	
	/*
	if (use_hmac){
	
		if(encrypted.size() < 32){
			return data;
		}
	
		Vector<uint8_t> hash;
		Vector<uint8_t> hashCalculated;
		
		hash.resize(32);
			
		for(size_t i =0;i<32;i++){
			hash[i] = encrypted[i]; //Get the hash
		}
				
		for(size_t i =0;i<encrypted.size()-32;i++){
			encrypted[i] = encrypted[i+32]; //Removing the hash from the front
		}
		
		encrypted.resize(encrypted.size()-32); //Removing the left over from the back
		
		hashCalculated = create_HMAC(encrypted);
			
		bool correct = true;
		
		for(size_t i=0;i<32;i++){
		
			if(hashCalculated[i] != hash[i]){
				correct = false;
				//You do not want to exit early as that introduces a timing attack
			}
		}
		
		if(!correct){
			std::cout << "noMatch" << std::endl;
			return data; //Empty Array
		}
		
		
	}
	
	Vector<uint8_t> iv;
	iv.resize(16);
	for(size_t i=0;i<16;i++){
		iv[i] = encrypted[i]	;	
	}
	
	
	for(size_t i=16;i<encrypted.size();i++){
		encrypted[i-16]		= encrypted[i];
	}
	
	encrypted.resize(encrypted.size()-16);
	
	std::cout << std::dec << encrypted.size() << std::endl;
	
	unsigned char* plaintext= new unsigned char[encrypted.size()];
	
	int decrypt_len = decrypt(encrypted.ptr(), encrypted.size(),keyToUse, iv.ptr(), plaintext);
  
  
	data.resize(decrypt_len); 
	
	
	for(size_t i=0;i<decrypt_len;i++){
		data[i]		= plaintext[i];
	}
	
	
	return data;*/
}

void Crypto::_bind_methods(){

    ObjectTypeDB::bind_method("set_password",&Crypto::set_password);
    ObjectTypeDB::bind_method("set_key",&Crypto::set_key);
    ObjectTypeDB::bind_method("set_HMAC",&Crypto::set_HMAC);
	
	
    ObjectTypeDB::bind_method("encrypt_string",&Crypto::encrypt_string);
    ObjectTypeDB::bind_method("encrypt_raw",&Crypto::encrypt_raw);
	
    ObjectTypeDB::bind_method("decrypt_string",&Crypto::decrypt_string);
    ObjectTypeDB::bind_method("decrypt_raw",&Crypto::decrypt_raw);
	
    ObjectTypeDB::bind_method("create_HMAC",&Crypto::create_HMAC);
	
}

