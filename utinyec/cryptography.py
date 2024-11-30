#WARNING: **This is not a library suitable for production.** It is useful for security professionals to understand the inner workings of EC, and be able to play with pre-defined curves.
#No really! This module has NOT been checked by any security or cryptographic professional, it should NOT be used in production.

import utinyec.registry as reg
import utinyec.ec as tinyec
from uos import urandom
from ucryptolib import aes

#ECcrypto class derived from ucryptolib documentation:
#https://hwwong168.wordpress.com/2019/09/25/esp32-micropython-implementation-of-cryptographic/

class uECcrypto:
    def __init__(self, curve_name="secp256r1", private_key_int=None):
        self.curve = self.get_curve_from_name(curve_name)
        self.keypair, self.public_key_point = self.make_keypair(self.curve,private_key_int)
        self.block_size = 16

    def get_private_key_int(self):
        return self.keypair.priv

    def get_public_key(self):
        return (self.keypair.pub.x, self.keypair.pub.y)        

    def get_curve_from_name(self, curve_name):
        return reg.get_curve(curve_name)
    
    def make_keypair(self, curve, private_key_int=None):
        return tinyec.make_keypair(curve,private_key_int)

    def derive_shared_secret(self, public_key):
        shared_secret_point = self.keypair.priv * public_key
        x_coordinate = shared_secret_point.x
        field_p = shared_secret_point.curve.field.p

        bit_len = tinyec.get_bit_length(field_p)
        byte_len = (bit_len + 7) // 8
        shared_secret = int.to_bytes(x_coordinate, byte_len, 'big')

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


if __name__ == '__main__':
    # Example usage:
    specified_private_key_int = None
    ecc_aes = uECcrypto('secp256r1', specified_private_key_int) #secp256r1 #brainpoolP256r1
    curve = reg.get_curve('secp256r1')
    keypair, public_key = tinyec.make_keypair(curve)

    #other_keypair = tinyec.make_keypair(reg.get_curve('secp256r1'))
    #public_key = other_keypair.pub

    plaintext = 'This is AES cryptographic'
    encrypted_cbc = ecc_aes.encrypt(plaintext, public_key, "CBC")
    decrypted_cbc = ecc_aes.decrypt(encrypted_cbc, public_key, "CBC")

    print('private_key:', ecc_aes.keypair.priv)
    print('public_key:', f"x{ecc_aes.keypair.pub.x}y{ecc_aes.keypair.pub.y}")
    print('other_public_key:', public_key)
    print('AES-CBC encrypted:', encrypted_cbc)
    print('AES-CBC decrypted:', decrypted_cbc.strip())

