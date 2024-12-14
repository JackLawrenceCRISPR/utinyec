#WARNING: **This is not a library suitable for production.** It is useful for security professionals to understand the inner workings of EC, and be able to play with pre-defined curves.
#No really! This module has NOT been checked by any security or cryptographic professional, it should NOT be used in production.

import utinyec.registry as reg
import utinyec.ec as tinyec
from uos import urandom
from ucryptolib import aes

import hmac 
import hashlib 

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

    def hkdf_expand(self, prk, info=b'', dklen=32):
        """HKDF expand function."""
        t = b''
        output_len = 0
        block_index = 1

        while output_len < dklen:
            hmac_obj = hmac.new(prk, t + info + bytes([block_index]), hashlib.sha256)
            t = hmac_obj.digest()
            output_len += len(t)

        return t[:dklen]

    def hkdf_extract(self, salt, ikm):
        """HKDF extract function."""
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    def derive_shared_secret(self, public_key, info=b'handshake data'):
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
        shared_secret_seed = int.to_bytes(x_coordinate, byte_len, 'big')
   
        # Extract with HKDF (use HMAC-SHA256 with zero-length salt to produce PRK)
        prk = self.hkdf_extract(b'', shared_secret_seed)
        # Expand with HKDF (expand PRK into symmetric key of desired length using info)
        shared_secret = self.hkdf_expand(prk, info, dklen=32)  # dklen needs to be 256 bits (32) for AES-256

        if self.public_key_caching == True and public_key.curve == self.curve:
            self.add_public_key_to_cache( (public_key.x,public_key.y) ,shared_secret)

        return shared_secret


    def pkcs7_pad(self, data, block_size):
        pad_length = block_size - (len(data) % block_size)
        padding_bytes = bytes([pad_length] * pad_length)
        padded_data = data + padding_bytes
        return padded_data
    
    def pkcs7_unpad(self, data):
        pad_length = data[-1]
        if not (1 <= pad_length <= 16):
            raise ValueError("Invalid padding")
        unpadded_data = data[:-pad_length]
        return unpadded_data







    def encrypt(self, plaintext, public_key, info=b'handshake data', mode="CBC"):
        key = self.derive_shared_secret(public_key, info)
        padded_plaintext = self.pkcs7_pad(plaintext, self.block_size) ##NEW

        if mode == "ECB":
            cipher = aes(key, 1)
            
            encrypted = cipher.encrypt(padded_plaintext)    
            #print('AES-ECB encrypted:', encrypted )

            #cipher = aes(key,1) # cipher has to renew for decrypt 
            #decrypted = cipher.decrypt(encrypted)
            #print('AES-ECB decrypted:', decrypted)
            return encrypted
        elif mode == "CBC":
            iv = urandom(self.block_size)
            cipher = aes(key,2,iv)

            ct_bytes = iv + cipher.encrypt(padded_plaintext)    
            #print ('AES-CBC encrypted:', ct_bytes)

            #iv = ct_bytes[:self.block_size]
            #cipher = aes(key,2,iv)
            #decrypted = cipher.decrypt(ct_bytes)[self.block_size:]
            #print('AES-CBC decrypted:', decrypted)
            return ct_bytes



    def decrypt(self, ciphertext, public_key, info=b'handshake data', mode="CBC"):
        key = self.derive_shared_secret(public_key, info)
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

            decrypted_with_iv = cipher.decrypt(ct_bytes)
            decrypted_text = decrypted_with_iv[self.block_size:]

            # Unpad the decrypted text
            unpadded_decrypted_text = self.pkcs7_unpad(decrypted_text)
            #print('AES-CBC decrypted:', decrypted)
            return unpadded_decrypted_text
        else:
            raise ValueError(f"Unknown mode: {mode}. Please choose from 'CBC' or 'ECB', where CBC is most secure.")
