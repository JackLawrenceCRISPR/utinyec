# -*- coding: utf-8 -*-
from uos import urandom #CHANGE: random to uos.urandom
#by the way, os.urandom and urandom are NOT the same
#urandom is a micropython optimised random module
#os.urandom is a function to get a string of size random bytes suitable for cryptographic use (supposedly)
#uos is os optimised for microcontollers so we use it instead of os

#import warnings    #CHANGE: dropped warnings dependency

#CHANGE: added two functions which are natively available in python, but not micropython
def get_bit_length(value):  #gets the bit length of an input, same as .bit_length() on an int in regular python
    if value == 0:
        return 1
    bit_length = 0
    while value > 0:
        value >>= 1
        bit_length += 1
    return bit_length

def get_random_big_number(max_value): #like math.random(x) where x is bigger than sys.maxsize
    #calculate bit length of max value and round up to nearest multiple of 8
    bit_length = ((get_bit_length(max_value) + 7) // 8) * 8
    
    #calculate number of bytes needed for desired bit length
    byte_length = (bit_length + 7) // 8
    
    while True:
        #generate random bytes
        random_bytes = urandom(byte_length)
        
        #convert byte sequence to a big integer
        random_number = int.from_bytes(random_bytes, 'big')
        
        #ensure random number is within the desired range
        if random_number <= max_value:
            return random_number

# Python3 compatibility
try:
    LONG_TYPE = long
except NameError:
    LONG_TYPE = int

#CHANGE: updated the egcd function to use a while loop rather than recursion, as micropython only has an recursion depth of 20 
#def egcd(a, b):	
#    if a == 0:
#        return b, 0, 1
#    else:
#        g, y, x = egcd(b % a, a)
#        return g, x - (b // a) * y, y
def egcd(a, b):
    x0, x1 = 0, 1
    y0, y1 = 1, 0

    while a != 0:
        q, b, a = b // a, a, b % a
        y0, y1 = y1, y0 - q * y1
        x0, x1 = x1, x0 - q * x1

    return b, x0, y0


def mod_inv(a, p):
    if a < 0:
        return p - mod_inv(-a, p)
    g, x, y = egcd(a, p)
    if g != 1:
        raise ArithmeticError("Modular inverse does not exist")
    else:
        return x % p


class Curve(object):
    def __init__(self, a, b, field, name="undefined"):
        self.name = name
        self.a = a
        self.b = b
        self.field = field
        self.g = Point(self, self.field.g[0], self.field.g[1])

    def is_singular(self):
        return (4 * self.a**3 + 27 * self.b**2) % self.field.p == 0

    def on_curve(self, x, y):
        return (y**2 - x**3 - self.a * x - self.b) % self.field.p == 0

    def __eq__(self, other):
        if not isinstance(other, Curve):
            return False
        return self.a == other.a and self.b == other.b and self.field == other.field

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "\"%s\" => y^2 = x^3 + %dx + %d (mod %d)" % (self.name, self.a, self.b, self.field.p)


class SubGroup(object):
    def __init__(self, p, g, n, h):
        self.p = p
        self.g = g
        self.n = n
        self.h = h

    def __eq__(self, other):
        if not isinstance(other, SubGroup):
            return False
        return self.p == other.p and self.g == other.g and self.n == other.n and self.h == other.h

    def __ne__(self, other):
        return not self.__eq__(other)

    def __str__(self):
        return "Subgroup => generator %s, order: %d, cofactor: %d on Field => prime %d" % (self.g, self.n,
                                                                                           self.h, self.p)

    def __repr__(self):
        return self.__str__()


class Inf(object):
    def __init__(self, curve, x=None, y=None):
        self.x = x
        self.y = y
        self.curve = curve

    def __eq__(self, other):
        if not isinstance(other, Inf):
            return False
        return self.curve == other.curve

    def __ne__(self, other):
        return not self.__eq__(other)

    def __add__(self, other):
        if isinstance(other, Inf):
            return Inf()
        if isinstance(other, Point):
            return other
        raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

    def __sub__(self, other):
        if isinstance(other, Inf):
            return Inf()
        if isinstance(other, Point):
            return other
        raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

    def __str__(self):
        return "%s on %s" % (self.__class__.__name__, self.curve)

    def __repr__(self):
        return self.__str__()


class Point(object):
    def __init__(self, curve, x, y):
        self.curve = curve
        self.x = x
        self.y = y
        self.p = self.curve.field.p
        self.on_curve = True
        if not self.curve.on_curve(self.x, self.y):
            #warnings.warn("Point (%d, %d) is not on curve \"%s\"" % (self.x, self.y, self.curve)) 
            print("Warning: Point (%d, %d) is not on curve \"%s\"" % (self.x, self.y, self.curve)) #CHANGE: dropped warnings dependency
            self.on_curve = False

    def __m(self, p, q):
        if p.x == q.x:
            return (3 * p.x**2 + self.curve.a) * mod_inv(2 * p.y, self.p)
        else:
            return (p.y - q.y) * mod_inv(p.x - q.x, self.p)

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return self.x == other.x and self.y == other.y and self.curve == other.curve

    def __ne__(self, other):
        return not self.__eq__(other)

    def __add__(self, other):
        if isinstance(other, Inf):
            return self
        if isinstance(other, Point):
            if self.x == other.x and self.y != other.y:
                return Inf(self.curve)
            elif self.curve == other.curve:
                m = self.__m(self, other)
                x_r = (m**2 - self.x - other.x) % self.p
                y_r = -(self.y + m * (x_r - self.x)) % self.p
                return Point(self.curve, x_r, y_r)
            else:
                raise ValueError("Cannot add points belonging to different curves")
        else:
            raise TypeError("Unsupported operand type(s) for +: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

    def __sub__(self, other):
        if isinstance(other, Inf):
            return self.__add__(other)
        if isinstance(other, Point):
            return self.__add__(Point(self.curve, other.x, -other.y % self.p))
        else:
            raise TypeError("Unsupported operand type(s) for -: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

    def __mul__(self, other):
        if isinstance(other, Inf):
            return Inf(self.curve)
        if isinstance(other, int) or isinstance(other, LONG_TYPE):
            if other % self.curve.field.n == 0:
                return Inf(self.curve)
            if other < 0:
                addend = Point(self.curve, self.x, -self.y % self.p)
            else:
                addend = self
            result = Inf(self.curve)
            # Iterate over all bits starting by the LSB
            for bit in reversed([int(i) for i in bin(abs(other))[2:]]):
                if bit == 1:
                    result += addend
                addend += addend
            return result
        else:
            raise TypeError("Unsupported operand type(s) for *: '%s' and '%s'" % (other.__class__.__name__,
                                                                                  self.__class__.__name__))

    def __rmul__(self, other):
        return self.__mul__(other)

    def __str__(self):
        return "(%d, %d) %s %s" % (self.x, self.y, "on" if self.on_curve else "off", self.curve)

    def __repr__(self):
        return self.__str__()


#CHANGE to make_keypairs:
# 1. modified function to allow predetermined private_key_int
# 2. ranint can't handle large integers in micropython, so it now uses the custom random big number function defined earlier
# 3. it now returns the public key coordinates for ease of use
def make_keypair(curve, private_key_int = None):
    #priv = random.randint(1, curve.field.n)
    if private_key_int is None:
        private_key_int = get_random_big_number(curve.field.n - 2) + 1
    pub = private_key_int * curve.g
    return Keypair(curve, private_key_int, pub), pub


class Keypair(object):
    def __init__(self, curve, priv=None, pub=None):
        if priv is None and pub is None:
            raise ValueError("Private and/or public key must be provided")
        self.curve = curve
        self.can_sign = True
        self.can_encrypt = True
        if priv is None:
            self.can_sign = False
        self.priv = priv
        self.pub = pub
        if pub is None:
            self.pub = self.priv * self.curve.g


class ECDH(object):
    def __init__(self, keypair):
        self.keypair = keypair

    def get_secret(self, keypair):
        # Don;t check if both keypairs are on the same curve. Should raise a warning only
        if self.keypair.can_sign and keypair.can_encrypt:
            secret = self.keypair.priv * keypair.pub
        elif self.keypair.can_encrypt and keypair.can_sign:
            secret = self.keypair.pub * keypair.priv
        else:
            raise ValueError("Missing crypto material to generate DH secret")
        return secret
