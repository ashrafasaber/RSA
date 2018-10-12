"""
*  Authors: Ashraf Saber, Dishen Zhao
*
*  Description: Crack and decrypt weak RSA, or encrypt using
*      user provided RSA public parameters.
*
*      Encryption: 
*
*      Decryption: Given ct, N, and e, solves for d and computes
*      plaintext message for weak RSA. Uses basic Fermat
*      factorization method which relies on 2 prime factors
*      of N being relaltively similar to close to sqrt(N).
*      Specifically used for Not-so-secret message from Malawi.
*
*  https://www.mysterytwisterc3.org/en/challenges/level-ii/not-so-secret-message-from-malawi--part-i-rsa
*
*  Usage: pycrack.py (no arguments for interactive mode)
*  Usage: pycrack.py <file>
*
*  File format by lines for encrypt
*  1: plaintext string
*  2: public RSA parameter N
*  3: public RSA parameter e
*
*  File format by lines for decrypt
*  1: ciphertext number
*  2: public RSA parameter N
*  3: public RSA parameter e
*  4: optional number of bits to keep from least signicant bits
"""

import random
import sys

# Find square root of a number rounded down to int, similar to int(math.sqrt(n))
# Newton's method integer square root, constantly improve approximation
# Return: int(x)
def isqrt(n):
  x = n
  y = (x + 1) // 2

  while y < x:
    x = y
    y = (x + n // x) // 2

  return x

# Find modular multiplicative inverse for e mod n
# Uses extended Euclidean algorithm ex + ny = 1, solve for x
# Return int(x)
def mod_mul_inverse(e, n):
  n_initial = n
  x = 1
  y = 0

  while e > 1:
    q = e // n

    t = n

    n = e % n
    e = t
    t = y

    y = x - q * y
    x = t

  if x < 0:
    x = x + n_initial

  return x

# Check if given number x is perfect square
# Return: boolean
def check_perfect_square(n):
  last_digit = n % 10
  prev_digit = (n // 10) % 10
  
  # Perfect square last digit must be 0, 1, 4, 5, 6, or 9
  if last_digit not in (0, 1, 4, 5, 6, 9):
    return False

  # Check 2nd to last digit based on last digit
  # 1, 4, 9: 2nd to last digit should be even
  if (last_digit in (1, 4, 9) and prev_digit % 2 != 0):
    return False

  # 0: 2nd to last digit should also be 0
  if last_digit == 0 and prev_digit != 0:
    return False

  # 5: 2nd to last digit should be 2
  if last_digit == 5 and prev_digit != 2:
    return False

  # 6: 2nd to last digit should be odd
  if last_digit == 6 and prev_digit % 2 != 1:
    return False

  # Manual check using square root function, check n - sqrt(n)^2 = 0
  check_perfect_square.count += 1
  r = isqrt(n)
  if n - r * r != 0:
    return False

  # Passed on tests, n is a perfect square
  return True
check_perfect_square.count = 0

# Fermat factorization to factor N into p, q
# Return: set(int(p), int(q))
def fermat_factor(n):
  a = isqrt(n)
  b2 = a * a - n
  loop_iterations = 0

  # Continue until b^2 is a perfect square of b * b
  while check_perfect_square(b2) == False:
    loop_iterations += 1
    a = a + 1
    b2 = a * a - n

  # p = a - b
  # q = a + b
  b = isqrt(b2)

  print("fermat_factor() loop count: {}".format(loop_iterations))
  print("manual perfect square checks: {}".format(check_perfect_square.count))
  return ((a-b), (a+b))

# Factor N into p, q and find mod mul inverse for private key d
# Return: int(d)
def crack_key(n, e):
  # Find 2 prime factors of n through Fermat facortization
  p, q = fermat_factor(n)

  # Calculate totient
  p = p - 1
  q = q - 1
  t = p * q

  # Calculate and return mod inverse
  return mod_mul_inverse(e, t)

def encrypt(ptmessage,N,e):

    #####################################
    # encryption math:                  #
    # c = m ^ e(mod n)                  #
    # cipherText = (ptmessage ^ e)mod N #
    #####################################

   # ptmessage     = "a" # for debugging
    ptmessage_bin = ""
    concat_pt     = ""
    cipherText    = ""
    # Step 1: Convert plaintext message into binary
    for i in range(len(ptmessage)):
        ptmessage_bin = bin(ord(ptmessage[i]))
        ptmessage_bin = ptmessage_bin[2:]
        ptmessage_bin = ptmessage_bin.zfill(8)
        # Step 2: Concatenate the binary
        concat_pt     += ptmessage_bin
        # print(concat_pt) # for debugging

    # Step 3: Convert the binary into int
    # print(int(concat_pt, 2)) # for debugging
    m = int(concat_pt, 2)
    # Step 4: Do the encryption math
    cipherText= (pow(m,e)) % N
    return cipherText

def encrypt_padding(ptmessage,N,e):

    #####################################
    # encryption math:                  #
    # c = m ^ e(mod n)                  #
    # cipherText = (ptmessage ^ e)mod N #
    #####################################
    v= random.random()
    # ptmessage     = "a"  # for debugging
    ptmessage_bin = ""
    concat_pt     = ""
    cipherText    = ""

    # Step 0: Calculate padding
    r_int = random.randint(1, 100000000000000000000000000)
    r_bin = bin(r_int)[2:].zfill(8)

    concat_pt += r_bin

    # Step 1: Convert plaintext message into binary
    for i in range(len(ptmessage)):
        ptmessage_bin = bin(ord(ptmessage[i]))
        ptmessage_bin = ptmessage_bin[2:]
        ptmessage_bin = ptmessage_bin.zfill(8)
        # Step 2: Concatenate the binary
        concat_pt     += ptmessage_bin
        # print(concat_pt) # for debugging

    # Step 3: Convert the binary into int
    # print(int(concat_pt, 2)) # for debugging
    m = int(concat_pt, 2)
    # Step 4: Do the encryption math
    cipherText= (pow(m,e)) % N
    print(r_int)
    print(r_bin)
    print(concat_pt)
    return cipherText

# Decrypt ciphertext to plaintext message for Not-so-Secret Message from Malawi
def decrypt(ct, n, d, keep_bits = 0):
  # RSA decryption pt = ct^d mod N
  pt = pow(ct, d, n)

  # To remove padding, take pt mod 2^(keep_bits)
  if keep_bits != 0:
    keep = 2 ** keep_bits
    pt = pt % keep
  
  # Convert every 1 byte into a char for decrypted message
  message = ""
  while pt > 0:
    c = pt % 256
    message = chr(c) + message
    pt = pt // 256

  return message

def main():
  # Print usage if wrong number of arguments
  if len(sys.argv) > 4:
    print("Usage: pycrack.py (no arguments for interactive mode)")
    print("Usage: pycrack.py [e|d] <file>")
    print("")
    print("File format by lines for encrypt")
    print("1: plaintext string")
    print("2: public RSA parameter N")
    print("3: public RSA parameter e")
    print("")
    print("File format by lines for decrypt")
    print("1: ciphertext number")
    print("2: public RSA parameter N")
    print("3: public RSA parameter e")
    print("4: optional number of bits to keep from least signicant bits")
    return
  
  # Interactive mode
  elif len(sys.argv) == 1:
    mode = input("Please enter e for encrypt or d for decrypt: ")
    # Encryption
    if mode == "e":
      try:
        pt = input("Please enter plaintext message string: ")
        n = int(input("Please enter public RSA parameter N: "))
        e = int(input("Please enter encryption exponent e: "))
        pad = input("Would you like to add padding? (y/n): ")
      except ValueError:
        print("Input on N or e could not be parsed as number!")
        return

      if pad == "y":
        ct = encrypt_padding(pt, n, e)
      elif pad == "n":
        ct = encrypt(pt, n, e)
      else:
        printf("Did not understand answer to padding question!")
        return
      
      print(ct)

    # Key cracking and decryption
    elif mode == "d":
      try:
        ct = int(input("Please enter ciphertext number: "))
        n = int(input("Please enter public RSA parameter N: "))
        e = int(input("Please enter encryption exponent e: "))
        keep_bits = int(input("Please enter number of bits representing length of original message, 0 for unknown: "))
      except ValueError:
        print("Input could not be parsed as number!")
        return

      d = crack_key(n, e)
      pt = decrypt(ct, n, d, keep_bits)
      print(pt)

    # Invalid mode
    else:
      print("Invalid option \"{}\"!".format(mode))
      return

  # Run with command line arguments as input
  elif len(sys.argv) > 1:
    # Encryption
    if sys.argv[1] == "e":
      with open(sys.argv[2]) as file:
        try:
          pt = file.readline().rstrip('\n')
          n = int(file.readline())
          e = int(file.readline())
        except ValueError:
          print("File \"{}\" lines could not be read as long number!".format(file.name))
          return

        ct = encrypt(pt, n, e)
        print(ct)

    # Cracking and decryption
    elif sys.argv[1] == "d":
      # Open file and read lines in order: ciphertext, N, e, keep_bits
      with open(sys.argv[2]) as file:
        try:
          ct = int(file.readline())
          n = int(file.readline())
          e = int(file.readline())
          keep_bits = file.readline()
          if keep_bits == '':
            keep_bits = 0
          else:
            keep_bits = int(keep_bits)
        except ValueError:
          print("File \"{}\" lines could not be read as long number!".format(file.name))
          return

        # Use Fermat factorization to find p, q
        # Then find mod mul inverse of e mod (p-1)(q-1)
        d = crack_key(n, e)

        # Use cracked private key d to decrypt the ciphertext into plaintext message
        pt = decrypt(ct, n, d, keep_bits)
        print(pt)

    # Invalid mode
    else:
      print("Invalid option \"{}\"".format(sys.argv[1]))

    
if __name__ == "__main__":
  main()
