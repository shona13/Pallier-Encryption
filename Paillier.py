import timeit
import gmpy2 as gmp
from random import randint

'''
    Author : Sonal Joshi
    Description : Paillier encryption scheme implementation using gmpy2 library

'''


# Key generation - Takes parameters prime p, prime q, and n = p*q
def key_gen(p,q,n):
    # Calculates g (Special case)
    g = n + 1
    # Calculates lambda
    lm = (p-1)*(q-1)
    return g,lm


# Randomly generates random number r for 128 bit security level
def random_num():
    state = gmp.random_state(hash(gmp.random_state()))
    r = gmp.mpz_urandomb(state, gmp.mpz('3072'))
    # Checking for gcd of (r,n) = 1 i.e Check if r belongs to Zn*
    while gmp.gcd(r,n) != gmp.mpz(1):
        r = gmp.mpz_urandomb(state, gmp.mpz('3072'))
    return r


# Encryption function - Takes parameters  generator g, composite modulus n, and message m
def encrypt(g,n,m):
    # Creating an object
    r = random_num()
    # n^2 variable
    square_n = gmp.mpz(n*n)
    # Encrypts the message and generates cipher
    cipher = gmp.mod(gmp.mul(gmp.powmod(g,m,square_n),gmp.powmod(r,n,square_n)),square_n)
    return r,cipher


# Decryption function - Takes parameters cipher c, composite modulus n & ciphertext c
def decrypt(c,n,lm):
    # n^2 variable
    square_n = gmp.mpz(n*n)
    # Calculates inverse of lambda
    inv_lm = gmp.invert(lm, n)
    # Computes the L(x) function = [(x - 1)/n] mod n
    x = gmp.sub(gmp.powmod(c, lm, square_n), gmp.mpz(1))
    # Decryption formula (X * Inverse of lambda)mod n
    decm = gmp.mod(gmp.mul(gmp.f_div(x, n), inv_lm), n)
    return decm


# Main function
if __name__ == '__main__':
    # Prime number p (given)
    p = gmp.mpz(91384202109071442293463836021112242872202112556997233738650771115304627068435244189452217404518350934650625169787645878831492249234702966702870665364147218752886578786376766042770107058123323172961898496290467790495229761191517699758387645314555098976305458147233083947409856486295027584628343852346198294834673398056518565970306137057662042381108071850367597403128086501769091999204250111973206216989075174484334959172281822465253170809350903328437985069427319)
    # Prime number q (given)
    q = gmp.mpz(81461618609951926714232486073323681843605711813586129469089521881286578240351609211470308250561781558375310490543983933780038328473513066035201591085583608631590043360965785867067725207262314428957973642440166838678305658012018727393737744349209249924848069061992265051686526452564260097993214532057415090837113730859560081637862504223208931316591467688041729971515846931082731879867661935144206080893902297595573259652166808407688180529379028374251689469303983)
    # Prime number n = p*q (given)
    n = gmp.mpz(p*q)
    # Generating random message in Zn* ie 1<m<n
    m = gmp.mpz(randint(1,n-1))

    '''
        Calling the functions
    '''
    # Creating an object of key_gen function & unpacking the returned tuples
    g,lm = key_gen(p,q,n)
    # Creating an object of encrypt function and unpacking the returned tuples
    r,ci = encrypt(g,n,m)
    # Creating an object of decrypt function
    dec = decrypt(ci,n,lm)


    ''' 
        Printing values on terminal
    '''
    ### Key Generation ###
    print("-"*10, "Key generation", "-"*10)
    print(f"The first prime is p = {p} \nThe second prime is q = {q}\nThe composite modulus is n = {n}")
    print(f"The encryption exponent is \u03BB = {lm}\nPublic key is pk (g,n) = ({g},{n}) \nPrivate Key is sk (p,q,\u03BB) = ({p},{q},{lm})\n")

    ### Encryption process ###
    print("-"*12, "Encryption", "-"*12)
    print(f"\nPlaintext  (randomly generated) is m = {m} \nThe random number is r = {r} \nCiphertext is c = {ci}\n")

    ### Decryption process ###
    print("-" * 12, "Decryption", "-" * 12)
    print(f"Ciphertext to be decrypted c = {ci} \nDecrypted plaintext is m = {dec}")

    ### Time taken to execute the program ###
    print("\nTime taken to run (seconds): ", timeit.timeit())