"""
These two functions are implementations of the RSA encryption decryption 
protocal created by Rivest, Shamir and Adleman. 

WARNING: Do not use these scripts in production settings! 
------------------------------------------------------------------------
Author : Tang U-Liang 
Email : tang_u_liang@sp.edu.sg 
------------------------------------------------------------------------
""" 
from random import randint
from sympy import randprime


def gcd(m, n):
    r = [m,n,m%n]
    
    while True:
        if r[2] == 0:
            break
        r = [r[1], r[2], r[1]%r[2]]
    
    return r[1]


def coprimeGen(n):
    """
    Returns a list of numbers coprime to n.
    """
    coprimes = list()
    add_in = coprimes.append
    
    for i in range(2, n):
        if gcd(i, n) == 1:
            add_in(i)
    
    return coprimes


def multpInv(x, n, mulp_group):
    """
    Returns x^-1 mod n
    """
    if x not in mulp_group: 
        raise ValueError("%d is not in multiplicative group" % (x))
        
    for y in mulp_group:
        if (x*y)%n == 1:
            return y


def lcm(x, y):
    return x*y/gcd(x, y)


def encrypt(message, public_key):
    e, n = public_key
    return pow(message, e, n)
    

def decrypt(c_message, private_key):
    d, n = private_key
    return pow(c_message, d, n)


def keygen():
    N = 10
    p = randprime(2**(N/2.0), 2**N)
    q = randprime(2**(N/2.0), 2**N)
    n = p*q
    
    lambda_n = lcm(p-1, q-1)
    
    coprime = coprimeGen(lambda_n)
    
    e = coprime[randint(0, len(coprime)-1)] # public exponent
    
    d = multpInv(e, lambda_n, coprime) # private exponent
    
    return (e, n), (d, n)