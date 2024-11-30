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
from utinyec.cryptography import uECcrypto
specified_private_key_int = None  #use a previous ecc_session.get_private_key_int() in here to use the same key pair
curve_name = 'secp256r1'  #see registry.py for a list of curve names
ecc_session = uECcrypto(curve_name, specified_private_key_int) #

#now we will generate a public_key position (x and y coordinates) which will represent the "other" public key being given to us
curve = reg.get_curve(curve_name)
keypair, other_public_key = tinyec.make_keypair(curve)

plaintext = 'This is AES cryptographic'
encrypted_cbc = ecc_session.encrypt(plaintext, other_public_key, "CBC")
decrypted_cbc = ecc_session.decrypt(encrypted_cbc, other_public_key, "CBC")

print('private_key:', ecc_session.keypair.priv)
print('public_key:', f"x{ecc_session.keypair.pub.x}y{ecc_session.keypair.pub.y}")
print('other_public_key:', other_public_key)
print('AES-CBC encrypted:', encrypted_cbc)
print('AES-CBC decrypted:', decrypted_cbc.strip())
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
