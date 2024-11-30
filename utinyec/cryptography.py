#WARNING: **This is not a library suitable for production.** It is useful for security professionals to understand the inner workings of EC, and be able to play with pre-defined curves.
#No really! This module has NOT been checked by any security or cryptographic professional, it should NOT be used in production.

import utinyec.registry as reg
import utinyec.ec as tinyec
from uos import urandom
from ucryptolib import aes

#ECcrypto class derived from ucryptolib documentation:
#https://hwwong168.wordpress.com/2019/09/25/esp32-micropython-implementation-of-cryptographic/

class uECcrypto:
    def __init__(self, curve_name="secp256r1", private_key_int=None, block_size=16, enable_public_key_caching=True):
        self.curve = self.get_curve_from_name(curve_name)
        self.keypair, self.public_key_point = self.make_keypair(self.curve,private_key_int)
        self.block_size = block_size
        self.public_key_caching = enable_public_key_caching
        self.public_key_cache = {}
    
    #public key -> shared secret caching
    def clear_public_key_cache(self):
        self.public_key_cache = {}
    
    def add_public_key_to_cache(self, public_key_tuple, derived_shared_secret):
        self.public_key_cache[public_key_tuple] = derived_shared_secret
    
    def check_public_key_cache(self,public_key_tuple):
        if isinstance(public_key_tuple,tuple) and len(public_key_tuple) == 2:
            #debug code for caching
            #print(r"___START_CACHE___")
            #print(public_key_tuple)
            #print(self.public_key_cache)
            #print(self.public_key_cache.get(public_key_tuple))
            #print(r"___END_CACHE___")
            return self.public_key_cache.get(public_key_tuple)
        else:
            public_key = self.make_public_key(public_key)
            if public_key.curve == self.curve:
                public_key_tuple = (public_key.x,public_key.y)
                return self.check_public_key_cache(public_key_tuple)
        return None        
        
    def set_public_key_caching(self,state):
        self.public_key_caching = state
        if not state:
            self.clear_public_key_cache()
    #end of caching

    def get_private_key_int(self):
        return self.keypair.priv

    def get_public_key(self):
        return (self.keypair.pub.x, self.keypair.pub.y)   #add curve name?   

    def make_public_key(self,x,y=None,curve=None):
        #you can just stuff all your values in the x coordinate, it's pretty flexible
        if isinstance (x,list) or isinstance(x, set):
            x = tuple(x)
            
        if isinstance(x,dict): #should probably be fed in as **dict but whatever
            curve = x.get("curve") or curve
            x = (x.get("x"),x.get("y"))

        if isinstance(x,tuple):
            if len(x) != 2:
                curve = x[2]
                x = (x,y)
        
        if curve is None:
            curve = self.curve
        if isinstance(curve,str):
            curve = self.get_curve_from_name(curve)
        
        #if y is None then x is in "cache" tuple format at this line, otherwise you can use (x,y) as the tuple
        
        if isinstance(x,tuple): 
            y = x[1]
            x = x[0]
        
        if x is None:
            raise ValueError("X coordinate not specified for make public key")
        if y is None:
            raise ValueError("Y coordinate not specified for make public key")
        
        return tinyec.Point(curve,x,y)

    def get_curve_from_name(self, curve_name):
        return reg.get_curve(curve_name)
    
    def make_keypair(self, curve, private_key_int=None):
        return tinyec.make_keypair(curve,private_key_int)

    def derive_shared_secret(self, public_key):
        if not isinstance(public_key, tinyec.Point):
            public_key = self.make_public_key(public_key)
            
        if self.public_key_caching == True and public_key.curve == self.curve:
            known_shared_secret = self.check_public_key_cache( (public_key.x,public_key.y) )
            if not (known_shared_secret is None):
                return known_shared_secret
            
        shared_secret_point = self.keypair.priv * public_key
        x_coordinate = shared_secret_point.x
        field_p = shared_secret_point.curve.field.p

        bit_len = tinyec.get_bit_length(field_p)
        byte_len = (bit_len + 7) // 8
        shared_secret = int.to_bytes(x_coordinate, byte_len, 'big')
        
        if self.public_key_caching == True and public_key.curve == self.curve:
            self.add_public_key_to_cache( (public_key.x,public_key.y) ,shared_secret)

        return shared_secret

    def encrypt(self, plaintext, public_key, mode="CBC"):
        key = self.derive_shared_secret(public_key)
        pad = self.block_size - len(plaintext) % self.block_size
        plaintext = plaintext + " "*pad
        
        if mode == "ECB":
            cipher = aes(key, 1)
            
            encrypted = cipher.encrypt(plaintext)
            #print('AES-ECB encrypted:', encrypted )

            #cipher = aes(key,1) # cipher has to renew for decrypt 
            #decrypted = cipher.decrypt(encrypted)
            #print('AES-ECB decrypted:', decrypted)
            return encrypted
        elif mode == "CBC":
            iv = urandom(self.block_size)
            cipher = aes(key,2,iv)

            ct_bytes = iv + cipher.encrypt(plaintext)
            #print ('AES-CBC encrypted:', ct_bytes)

            #iv = ct_bytes[:self.block_size]
            #cipher = aes(key,2,iv)
            #decrypted = cipher.decrypt(ct_bytes)[self.block_size:]
            #print('AES-CBC decrypted:', decrypted)
            return ct_bytes

    def decrypt(self, ciphertext, public_key, mode="CBC"):
        key = self.derive_shared_secret(public_key)
        if mode == "ECB":
            encrypted = ciphertext
            cipher = aes(key, 1)

            # Padding plain text with space 
            #pad = self.block_size - len(plaintext) % self.block_size
            #plaintext = plaintext + " "*pad

            #encrypted = cipher.encrypt(plaintext)
            #print('AES-ECB encrypted:', encrypted )

            cipher = aes(key,1) # cipher has to renew for decrypt 
            decrypted = cipher.decrypt(encrypted)
            #print('AES-ECB decrypted:', decrypted)
            return decrypted
        elif mode == "CBC":
            ct_bytes = ciphertext
            #iv = urandom(self.block_size)
            #cipher = aes(key,2,iv)

            #ct_bytes = iv + cipher.encrypt(plaintext)
            #print ('AES-CBC encrypted:', ct_bytes)

            iv = ct_bytes[:self.block_size]
            cipher = aes(key,2,iv)
            decrypted = cipher.decrypt(ct_bytes)[self.block_size:]
            #print('AES-CBC decrypted:', decrypted)
            return decrypted
