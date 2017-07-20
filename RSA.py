"""
This script implements the RSA encryption decryption 
protocal created by Rivest, Shamir and Adleman.  

WARNING: Do not use these scripts in production settings! 
------------------------------------------------------------------------
Author : Tang U-Liang 
Email : tang_u_liang@sp.edu.sg 
------------------------------------------------------------------------
""" 
from random import randint
from sympy import randprime
from numpy import floor, sqrt


def gcd(m, n):
    r = [m,n,m%n]
    s = [None, 1, 0]
    t = [None, 0, 1]
    
    while True:
        q = floor(r[0]/r[1])
        s = [s[1], s[2], s[1] - q*s[2]]
        t = [t[1], t[2], t[1] - q*t[2]]
        
        if r[2] == 0:
            break
        
        r = [r[1], r[2], r[1]%r[2]]
        
    
    return r[1], s[1], t[1]


def coprimeGen(n):
    """
    Returns a random prime coprime to n.
    """
    i = 2
    while i < n:
        p = randprime(i, n)
#        print p
        m, _, _ = gcd(p, n)
        if m == 1:
            break
        i += 1
    return p

def multpInv(x, n):
    """
    Returns x^-1 mod n
    """
    r, s, _ = gcd(x, n)
    if r != 1:
        raise ValueError("{} and {} are not coprime".format(x, n))
    else:
        return long(s)


def lcm(x, y):
    m, _, _ = gcd(x, y)
    return x*y/m


def encrypt(message, public_key):
    e, n = public_key
    return pow(message, e, n)
    

def decrypt(c_message, private_key):
    d, n = private_key
    return pow(c_message, d, n)


def keygen(N):
    """
    Generates cryptographically insecure key pairs with modulus between
    2N-1 to 2N bits. 
    """
    p = randprime(2**(N-1), 2**N)
    q = randprime(2**(N-1), 2**N)
    n = p*q
    
    

    lambda_n = lcm(p-1, q-1)
#    print lambda_n
    e = coprimeGen(lambda_n) # public exponent
    
    d = multpInv(e, lambda_n) # private exponent
    
    return (e, n), (d, n)