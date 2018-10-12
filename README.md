# RSA Cracking by Factorization

## Python
The main code "pycrack.py" is written in and tested on python 3.7

Usage: pycrack.py (no arguments for interactive mode)
Usage: pycrack.py <file>

File format by lines for encrypt\
1: plaintext string\
2: public RSA parameter N\
3: public RSA parameter e\

File format by lines for decrypt\
1: ciphertext number\
2: public RSA parameter N\
3: public RSA parameter e\
4: optional number of bits to keep from least signicant bits

## C
The extra C code "crack.c" is not for grading, just including old code
for comparison in the report. Makefile and build instructions not included
for C code. C code depends on external GMP library. If you decide to
install/link the GMP library and build the C program:

Usage: crack <file> [verbose]
