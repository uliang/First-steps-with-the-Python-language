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
from numpy import floor

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
    
    for i in xrange(n):
        p = randprime(i, n)
        if p%n == 1:
            return p
            break
        

def multpInv(x, n):
    """
    Returns x^-1 mod n
    """
    


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
    
    e = coprimeGen(lambda_n) # public exponent
    
    d = multpInv(e, lambda_n, coprime) # private exponent
    
    return (e, n), (d, n)