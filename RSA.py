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
import sys

if sys.version_info > (3,):
    long = int

class RSA(object):


    def __init__(self):
        self.n = None
        self.e = None
        self.__d = None
        self.c_message = None
        
    @property
    def d(self):
        _d = self.__d
        if self.__d is not None:
            self.__d = None
        return _d

    @staticmethod
    def _gcd(m, n):
        r0, r1 = m, n
        s0, s1 = 1, 0
        t0, t1 = 0, 1
        q, r = divmod(r0, r1)

        while r != 0:
#           print((r1, s1, t1))
            r0, r1 = r1, r
            s0, s1 = s1, s0 - q*s1
            t0, t1 = t1, t0 - q*t1
            q, r = divmod(r0, r1)
#           print(q)
        
        assert m*s1+n*t1 == r1

        if s1< 0:
            s1 += n
                
        if t1 < 0:
            t1 += m
        
        return r1, s1, t1

    @staticmethod
    def _coprimeGen(n):
        """
        Returns a random prime coprime to n.
        """
        max_iter = 1000
        i = 0
        p = randprime(1e4, min(n, 1e6))

        while p%n == 0:
            p = randprime(1e4, min(n, 1e6))
            if i > max_iter:
                raise RuntimeError("number coprime to {}".format(n)
                                   + " not found after max allowed iteration")
            i += 1
        return p

    def _multpInv(self, x, n):
        """
        Returns x^-1 mod n
        """
        r, _, t = self._gcd(n, x)
        if r != 1:
            raise ValueError("{} and {} are not coprime".format(x, n))
        else:
            return long(t)

    def _lcm(self, x, y):
        d, _, _ = self._gcd(x, y)
        return x*y//d

    def keygen(self, N):
        """
        Randomly generates cryptographically insecure key pairs
        with modulus between 2N-2 to 2N digits.
        """
        p = randprime(10**(N-1), 10**N)
        q = randprime(10**(N-1), 10**N)
        self.n = p*q
        
        lambda_n = self._lcm(p-1, q-1)
        
        if lambda_n < 1e4:
            raise ValueError("modulus is too short")

        self.e = self._coprimeGen(lambda_n) # public exponent
        self.__d = self._multpInv(self.e, lambda_n) # private exponent

        assert (self.e*self.__d)% lambda_n == 1

        return None
            
    def get_public_key(self):
        return (self.e, self.n)

'''
    def encrypt(self, message):

        if type(message) is not int and type(message) is not long:
            raise TypeError("Message must be either int or long type")

        if message > self.n:
            raise ValueError("Message is too long. Exceeds key length")

        self.c_message = pow(message, self.e, self.n)

        return None

    def decrypt(self, d):
        if self.c_message is None:
            raise ValueError("No message to decrypt")
        return pow(self.c_message, d, self.n)
  
    def get_c_message(self):
        return hex(self.c_message)
'''
