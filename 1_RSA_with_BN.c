#include <openssl/bn.h>
#include <openssl/err.h>
#include <stdio.h>


/*
1. implement the RSA key generation with OpenSSL Big Numbers
*/



int main() {
    printf("Hello, World!\n");
    BIGNUM *n=BN_new(), *p=BN_new(), *q=BN_new(), *one=BN_new(), *p_minus_one=BN_new(),
            *q_minus_one=BN_new(), *e=BN_new(), *d=BN_new(), *phi=BN_new(), *minus_one=BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if(!BN_generate_prime_ex(p, 32, 0, NULL, NULL, NULL)){
        ERR_print_errors_fp(stderr);
    }
    if(!BN_generate_prime_ex(q, 32, 0, NULL, NULL, NULL)){
        ERR_print_errors_fp(stderr);
    }

    BN_mul(n, p, q, ctx);

    BN_set_word(one, 1);
    BN_set_word(minus_one, -1);
    BN_sub(p_minus_one, p, one);
    BN_sub(q_minus_one, q, one);
    BN_mul(phi, p_minus_one, q_minus_one, ctx);

    BN_set_word(e, 65535);      // Fermat F_4 number
    BN_mod_inverse(d, e, phi, ctx);

    BN_print_fp(stdout, p);
    printf("\n");
    BN_print_fp(stdout, q);
    printf("\n");
    BN_print_fp(stdout, n);
    printf("\n");

    BN_print_fp(stdout, one);
    printf("\n");
    BN_print_fp(stdout, p_minus_one);
    printf("\n");
    BN_print_fp(stdout, q_minus_one);
    printf("\n");
    BN_print_fp(stdout, phi);
    printf("\n");
    BN_print_fp(stdout, e);
    printf("\n");
    BN_print_fp(stdout, d);
    printf("\n");

    return 0;
}
