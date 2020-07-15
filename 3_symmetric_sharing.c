//
// Created by Alessandro-Pisani on 15/07/2020.
//
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>

/*
the message length is limited to 2048 bits or 256 bytes, which is also our key size. A limitation of RSA is that you
cannot encrypt anything longer than the key size, which is 2048 bits in this case. Since  we’re reading in chars, which
are 1 byte and 2048 bits translates to 256 bytes, the theoretical max length of our message is 256 characters long
including the null terminator. In practice, this number is going to be slightly less because of the padding the encrypt
function tacks on at the end. This number is around 214 characters for a 2048 bit key.
*/
//3. generate a symmetric key and use OpenSSL RSA functions to exchange it

#define KEY_LENGTH 2048 //Asymmetric key length

int main(int argc, char** argv) {
    unsigned char key[1024];
    /*GENERATE ASYMMETRIC KEYS*/
    BIGNUM *bn_pub_exp = BN_new();
    BN_set_word(bn_pub_exp, RSA_F4);
    RSA *keypair = RSA_new();
    RSA_generate_key_ex(keypair, KEY_LENGTH, bn_pub_exp, NULL);

    /*GENERATE SYMMETRIC KEYS*/
    int key_size = EVP_CIPHER_key_length(EVP_aes_256_cbc());
    RAND_bytes(key, key_size);
    printf("key is: %s\n", key);

    /*ENCRYPT SYMMETRIC KEY*/
    int encrypted_data_len;
    char *encrypted_data=malloc(RSA_size(keypair));
    char* err = malloc(130);
    if((encrypted_data_len = RSA_public_encrypt(128,(unsigned char*) key,
            (unsigned char*)encrypted_data, keypair, RSA_PKCS1_OAEP_PADDING))== -1){
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
    }

    FILE *out = fopen("out.bin", "w");
    fclose(out);
    fwrite(encrypted_data, sizeof(*encrypted_data), RSA_size(keypair), out);

    /************************************************************************/

    out = fopen("out.bin", "r");
    fread(encrypted_data, sizeof(*encrypted_data), RSA_size(keypair), out);

    char *decrypted_data = (char*)malloc(encrypted_data_len);

    if(RSA_private_decrypt(encrypted_data_len, (unsigned char*) encrypted_data,
            (unsigned char*) decrypted_data, keypair, RSA_PKCS1_OAEP_PADDING)== -1){
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error decrypting message: %s\n", err);
    } else {
        printf("Decrypted message: %s\n", decrypted_data);
    }

    fclose(out);

    return 0;
}


