Group members: Ashraf Saber, Dishen Zhao
Challenge: Not-so-Secret Message from Malawi (Part I)
https://www.mysterytwisterc3.org/en/challenges/level-ii/not-so-secret-message-from-malawi--part-i-rsa

SOLVING THE CHALLENGE
The challenge given parameters are stored in "ct.txt". The order of parameters is described
in the python usage instructions. Solve the challenge and find the hidden message by using:

python pycrack.py d ct.txt

See output.txt for values of p, q, and d if interested. Verbose output not supported
in python program.

PYTHON PROGRAM
The main code "pycrack.py" is written in and tested on python 3.7

Usage: pycrack.py (no arguments for interactive mode)
Usage: pycrack.py <file>

File format by lines for encrypt
1: plaintext string
2: public RSA parameter N
3: public RSA parameter e

File format by lines for decrypt
1: ciphertext number
2: public RSA parameter N
3: public RSA parameter e
4: optional number of bits to keep from least signicant bits

C PROGRAM
The extra C code "crack.c" is not for grading, just including old code
for comparison in the report. Makefile and build instructions not included
for C code. C code depends on external GMP library. If you decide to
install/link the GMP library and build the C program:

Usage: crack <file> [verbose]
