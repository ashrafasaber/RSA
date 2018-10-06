import random

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

def main():
#    v=random.randint(1,100000000000000000000000000)
#    print(v)
#    vv = bin(v)[2:].zfill(8)
#    print(vv)
    message="a"
    Nval=3233
    eval=17
    print(encrypt_padding(message,Nval, eval))

main()

# references:
# https://pymotw.com/2/random/
# https://learning-python.com/strings30.html
# https://techtutorialsx.com/2018/02/04/python-converting-string-to-bytes-object/
# https://bytes.com/topic/python/answers/480700-how-convert-string-into-binary
# https://www.datacamp.com/community/tutorials/python-data-type-conversion#binocthex
# https://www.programiz.com/python-programming/methods/built-in/slice
# https://thispointer.com/python-how-to-iterate-over-the-characters-in-string/