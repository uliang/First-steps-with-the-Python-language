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
        r = [m, n, m%n]
        s = [None, 1, 0]
        t = [None, 0, 1]

        while True:
            q = r[0]//r[1]
            s = [s[1], s[2], s[1] - q*s[2]]
            t = [t[1], t[2], t[1] - q*t[2]]

            if r[2] == 0:
                break

            r = [r[1], r[2], r[1]%r[2]]

        if s[1] < 0:
            s[1] = s[1] + n
        return r[1], s[1], t[1]

    @staticmethod
    def _coprimeGen(n):
        """
        Returns a random prime coprime to n.
        """
        max_iter = 1000
        i = 0
        p = randprime(2, n)

        while p%n == 0:
            p = randprime(2, n)
            if i > max_iter:
                raise RuntimeError("number coprime to {}".format(n)
                                   + " not found after max allowed iteration")
            i += 1
        return p

    def _multpInv(self, x, n):
        """
        Returns x^-1 mod n
        """
        r, s, _ = self._gcd(x, n)
        if r != 1:
            raise ValueError("{} and {} are not coprime".format(x, n))
        else:
            return long(s)

    def _lcm(self, x, y):
        m, _, _ = self._gcd(x, y)
        return x*y/m

    def keygen(self, N):
        """
        Randomly generates cryptographically insecure key pairs
        with modulus between 2N-1 to 2N bits.
        """
        p = randprime(2**(N-1), 2**N)
        q = randprime(2**(N-1), 2**N)
        self.n = p*q

        lambda_n = self._lcm(p-1, q-1)

        self.e = self._coprimeGen(lambda_n) # public exponent
        self.__d = self._multpInv(self.e, lambda_n) # private exponent

        return None

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

    def get_public_key(self):
        return (self.e, self.n)

    def get_c_message(self):
        return hex(self.c_message)
