/* CS265 Project
*  Authors: Ashraf Saber, Dishen Zhao
*
*  Description: Given N and e, solves for d and computes
*      plaintext message for weak RSA. Uses basic Fermat's 
*      factorization method which relies on 2 prime factors
*      being relatively similar or close to sqrt(N).
*      Specifically used for Not-so-secret message from Malawi.
* 
*  https://www.mysterytwisterc3.org/en/challenges/level-ii/not-so-secret-message-from-malawi--part-i-rsa
*
*  Usage: ./crack <file> [verbose]
*
*  File format: Text file with 3 lines for given RSA parameters: 
*       First line is ciphertext, second is N, third is e.
*/

#include <gmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void decrypt(mpz_t ct, mpz_t N, mpz_t d) {
	char message[26] = "";
	mpz_t pt, pad;
	
	// Set pad to be 2^200
	mpz_init(pt);
	mpz_init_set_ui(pad, 2);
	mpz_pow_ui(pad, pad, 200);

	// RSA decryption: pt = ct^d mod N
	mpz_powm(pt, ct, d, N);

	// Remove padding by pt % pad
	// Considers only 200 lowest sig bits
	mpz_mod(pt, pt, pad);

	// Read long integer as ASCII 8-bit chars
	// pt % 256 retrieves last char, store backwards
	for (int i = 24; i >= 0; i--) {
		message[i] = (char)mpz_fdiv_q_ui(pt, pt, 256);
	}
	printf("message = %s\n", message);

	mpz_clears(pt, pad, NULL);
}

// Basic Fermat's factorization method with no optimization
// https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
void fermat_factor(mpz_t N, mpz_t p, mpz_t q) {
	mpz_t a, b2;

	mpz_inits(a, b2, NULL);

	// a = sqrt(N)
	mpz_sqrt(a, N);

	// b^2 = a^2 - N
	mpz_mul(b2, a, a);
	mpz_sub(b2, b2, N);
	
	// Continue until b^2 is perfect square of b * b
	while (mpz_perfect_square_p(b2) == 0) {
		// a = a + 1
		mpz_add_ui(a, a, 1);
		// b^2 = a^2 - N
		mpz_mul(b2, a, a);
		mpz_sub(b2, b2, N);
	}

	// p = a - b
	// q = a + b
	mpz_sqrt(p, b2);
	mpz_set(q, p);
	mpz_sub(p, a, p);
	mpz_add(q, a, q);

	mpz_clears(a, b2, NULL);
}

void crack_key(mpz_t N, mpz_t p, mpz_t q, mpz_t e, mpz_t d) {
	mpz_t t;
	mpz_init(t);

	// Factor N into p, q
	fermat_factor(N, p, q);

	// Compute Carmichael's totient (can also use Euler's)
	mpz_sub_ui(p, p, 1);
	mpz_sub_ui(q, q, 1);
  //mpz_mul(t, p, q);
	mpz_lcm(t, p, q);

	// Compute modular inverse of t(N) and e to find d
	mpz_invert(d, e, t);

	mpz_clear(t);
}

int main(int argc, char **argv) {
	// Declaration
	FILE *fp;
	char *buf = 0;
	size_t buf_len = 0;
	ssize_t read = 0;
	mpz_t ct, N, e, d, p, q;

	// Check correct argument count
	if (argc < 2 || argc > 3) {
		fprintf(stderr, "USAGE: %s <file> [verbose]\n", argv[0]);
		return 1;
	}

	// Initialization
	mpz_inits(ct, N, e, d, p, q, NULL);

	// Open and read file
	fp = fopen(argv[1], "r");
	if (fp == NULL) {
		fprintf(stderr, "Error opening or reading file!\n");
		return 1;
	}

	// Read lines in order: ciphertext, N, e
	read = getline(&buf, &buf_len, fp);
	if (read == -1) {
		fprintf(stderr, "Error reading line 1 from file!\n");
		return 1;
	}
	mpz_set_str(ct, buf, 10);
	

	read = getline(&buf, &buf_len, fp);
	if (read == -1) {
		fprintf(stderr, "Error reading line 2 from file!\n");
		return 1;
	}
	mpz_set_str(N, buf, 10);
	

	read = getline(&buf, &buf_len, fp);
	if (read == -1) {
		fprintf(stderr, "Error reading line 3 from file!\n");
		return 1;
	}
	mpz_set_str(e, buf, 10);
	

	// Solve for private key d
	crack_key(N, p, q, e, d);

	// Decrypt ciphertext using N and d into plaintext
	decrypt(ct, N, d);

	if (argc == 3 && strcmp(argv[2], "verbose")  == 0) {
		gmp_printf("ct = %Zd\n", ct);
		gmp_printf("N = %Zd\n", N);
		gmp_printf("p = %Zd\n", p);
		gmp_printf("q = %Zd\n", q);
		gmp_printf("e = %Zd\n", e);
		gmp_printf("d = %Zd\n", d);
	}

	// Free memory and close streams
	fclose(fp);
	free(buf);
	mpz_clears(N, e, d, p, q, NULL);

	return 0;
}
