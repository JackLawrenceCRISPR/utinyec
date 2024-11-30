# utinyec
A tiny library to perform potentially unsafe cryptography with arithmetic operations on elliptic curves in pure micropython. No dependencies.

**This is not a library suitable for production.** It is useful for security professionals to understand the inner workings of EC, and be able to play with pre-defined curves.
No really, this module has not been tested for vulnerabilities. It should never be used in production. I am not accountable for what you choose to do with this module.

utinyec shows the mathematics behind eliptical curve cryptography (ECC) in pure python which is useful for educational purposes. C based solutions with python API can be compiled from these two libraries: [ucryptography](https://github.com/dmazzella/ucryptography) or [ucrypto](https://github.com/dmazzella/ucrypto), they use C for the cryptography which is MUCH faster than pure python.

If you want to convert this from micropython to regular python then change "from uos import urandom" to "from os import urandom" in both ec.py AND cryptography.py, then change 'from ucryptolib import aes' to 'from cryptolib import aes' in cryptography.py. 
This package is very slow, and possibly unsafe as it has not been audited; if you need a cryptography solution in regular python please use pip install cryptography, or if you are using android you need to use 'apt install python-cryptography' as the rust dependency is dropped for functionality in Termux.

## installation in Micropython
`pip install utinyec`  
In Thonny you can find it in Tools -> Manage Packages, then search for utinyec.

## usage
```python
#Must be micropython, not regular python.
print('please be patient, this may take a while...')

#init:
from utinyec.cryptography import uECcrypto
specified_private_key_int = None  #use a previous alices_session.get_private_key_int() in here to use the same key pair
curve_name = 'secp256r1'  #see registry.py for a list of curve names
alices_session = uECcrypto(curve_name, specified_private_key_int) # derive_shared_secret AES256 keys are 
print('alices_session is ready...')

#now we will generate a public_key position (x and y coordinates) which will represent the "other" public key being given to us
bobs_session = uECcrypto(curve_name)
print('bobs_session is ready...')

#exchange keys over network, see examples below
alices_public_key = alices_session.get_public_key()
bobs_public_key = bobs_session.get_public_key()
print("bob and alice exchange public keys...")

#temporary keypair example:
#from utinyec import registry as reg
#from utinyec import ec as tinyec
#curve = reg.get_curve(curve_name)
#keypair, bobs_public_key = tinyec.make_keypair(curve) 
#
#this is one-sided, since we didn't really make an actual class. Not really that useful, but shows uECcrypto can be used as a component of a larger project from exposed api calls.
#encrypted_cbc = alices_session.encrypt(plaintext, bobs_public_key, "CBC")
#decrypted_cbc = alices_session.decrypt(encrypted_cbc, bobs_public_key, "CBC")
#

#example other_public_key formats:
#other_public_key = tinyec.make_public_key()
#
#other_public_key = (24186427586325584408744247601395677827137854066598587263728946626505599356143, 54693647365151360530247677535261819666420276295191767359408775310662222563936)
#
#other_public_key = {"x":24186427586325584408744247601395677827137854066598587263728946626505599356143,
#                    "y":54693647365151360530247677535261819666420276295191767359408775310662222563936,
#                    "curve":curve_name} #specifying "curve" is optional, the class will use it's own if none is provided. Curve can be a name or the Curve class object
#
#the dictionary format is particularly useful as it is JSON serializable for network transmission, you can create it with {"x":alices_session.keypair.x,"y":alices_session.keypair.y}
#then just import json (or ujson in micropython) and run ujson.dumps(public_key_dict) then use urequests with networking to send to another microcontroller for key exchange
#remember, this has not been validated and should not be used in production, only as an example to demonstrate how an ECC key exchange could work in a network


#cryptography demonstration
plaintext = 'This is AES cryptographic'.strip() #secret message that alice will send to bob, note that blank spaces will be trimmed due to block padding
print('alice is encrypting her message...')
encrypted_message = alices_session.encrypt(plaintext, bobs_public_key, "CBC")	#alices_session will encrypt using the derived shared secret
print('alice has encrypted her message and sends it to bob...')
decrypted_message = bobs_session.decrypt(encrypted_message, alices_public_key, "CBC")	#the second alices_session will derive the same shared secret with the other key combination, then decrypt the data
print('bob has decrypted alices message...')

#analysis of results:
print("")
print("RESULT:")
#what alice knows:
print("")
print("alices_session private",alices_session.keypair.priv) #alice shouldn't share this with anyone!
print('bobs_session public:',bobs_public_key)
alices_shared_secret = alices_session.derive_shared_secret(bobs_public_key)
print('alices shared secret:', alices_shared_secret) #this is faster with caching enabled, also alice shouldn't share this with anyone!

#what bob knows:
print("")
print("bobs_session private",bobs_session.keypair.priv) #bob shouldn't share this with anyone!
print('alices_session public:',alices_public_key)
bobs_shared_secret = bobs_session.derive_shared_secret(alices_public_key)
print('bobs shared secret:',bobs_session.derive_shared_secret(alices_public_key) ) #this is faster with caching enabled, also bob shouldn't share this with anyone!

#remember the man in the middle (MITM) knows both public keys, but should never know any private keys...
#in theory with Elliptical Curve Cryptography (ECC), deriving a shared secret from two public keys is not possible. Remember this is an example and should not be used in production.

print("")
print('Alices original message:',plaintext)
print('Encrypted message:', encrypted_message)
print('Alices message decrypted by Bob:', decrypted_message.strip())

assert bobs_shared_secret == alices_shared_secret, "Error: alice and bob derived different shared secrets!"
print("bob and alice have correctly derived the same shared secret")
assert plaintext == decrypted_message.decode('utf-8').strip(), "Error: bob's decrypted message is not the same as what alice sent!"
print("bob has correctly read alice's message")
print("Demonstration complete.")


#caching example
#try toggling off by using enable_public_key_caching=False as an argument in a uECcrypto init or.set_public_key_caching(False)
#if you do use caches (on by default) you can clear the cache by running .clear_public_key_cache()
print("")
print("Demonstrating caching...")
import utime
print("3")
utime.sleep(1)
print("2")
utime.sleep(1)
print("1")
utime.sleep(1)
print("GO")

plaintext2 = 'Alice likes eating apples.'.strip() #secret message that alice will send to bob, note that blank spaces will be trimmed due to block padding
print('alice is encrypting her second message...')
encrypted_message2 = alices_session.encrypt(plaintext2, bobs_public_key, "CBC")	#if caching is enabled this will be FAST
print('alice has encrypted her second message and sends it to bob...')
decrypted_message2 = bobs_session.decrypt(encrypted_message2, alices_public_key, "CBC")	#if caching is enabled this will be FAST
print('bob has decrypted alices second message...')
assert plaintext2 == decrypted_message2.decode('utf-8').strip(), "Error: bob's decrypted message is not the same as what alice sent!"
print("bob has correctly read alice's second message")
print("Caching demonstration complete.")
```


## PEM formatting
Using regular python (not micropython) you can use the cryptography module to convert from coordinate to standard PEM, or reverse.
Conversion may be useful when communicating with non-microcontroller devices, as devices using regular python can convert public keys to coordinates before sending them.
I do not know of a method to convert formats within micropython, and such a method is outside my personal use case for this project. Send the github repository a pull request if you write one!

### converting to and from PEM format
```python
#REGULAR python, NOT micropython
#I provide some public key coordinates for this example, but you should derive your own from the uECCrypto class
public_key_coordinates = (27080695663519936575286139140947921079432612852248858477930157300769994068404, 89650813448058425836500999002714743992773189021923677962194438343503940101997)
#the previous line is an EXAMPLE set of coordinates, you should use your own, see the next couple of lines which shows you where to get them
#public_key_coordinates = (ecc_session.keypair.pub.x, ecc_session.keypair.pub.y)
#public_key_coordinates = ecc_session.get_public_key()

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

def get_pem_from_ecc_coordinates(public_key_coordinates):
    #define curve SECP256R1 (for example)
    curve = ec.SECP256R1()
    x_coordinate, y_coordinate = public_key_coordinates

    #create public key object
    ec_public_key = ec.EllipticCurvePublicNumbers(x_coordinate, y_coordinate, curve).public_key()

    #serialize public key to PEM format
    return ec_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def get_ecc_coordinates_from_pem(pem_data):
    # deserialize PEM data to public key object
    ec_public_key = serialization.load_pem_public_key(pem_data)
    
    # extract public numbers from the public key
    public_numbers = ec_public_key.public_numbers()
    
    # return x and y coordinates
    return (public_numbers.x, public_numbers.y)



#USAGE:
print("original coordinates:", public_key_coordinates)

#convert to PEM
pem = get_pem_from_ecc_coordinates(public_key_coordinates)
print("derived PEM:", pem.decode('utf-8'))   #decode bytes to string format

#and convert back to coordinates
processed_public_key_coordinates = get_ecc_coordinates_from_pem(pem)    #pem is given as bytes by the way, not a string!
print("derived coordinates:", public_key_coordinates)
```
