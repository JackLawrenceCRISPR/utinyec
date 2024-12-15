import base64
from utinyec.cryptography import uECcrypto
import urequests as requests
import ujson as json

class VIPER_ECC:
    def __init__(self, private_key:int=None, curve_name:str="secp256r1"):
        #private key must be int
        self.session = uECcrypto(curve_name, private_key)
        self.private_key = self.session.keypair.priv

    def set_server_key(self, server_key:int):
        self.__init__(server_key)

    def set_server_url(self, new_url:str): 
        self.server_url = new_url

    def post(self, data:dict, extension:str=None, url:str=None, ensure_SSL:bool=True, custom_private_key:str=None):
        EncryptedPostData = None
        if custom_private_key is None:
            EncryptedPostData={
                "key":self.public_key_str,
                "encrypted_data":(self.encrypt(json.dumps(data)))
            }
        else:
            EncryptedPostData={
                "key":self.public_key_str,
                "encrypted_data":(self.encrypt_with_specified_private_key(json.dumps(data),custom_private_key))
            }
        
        Response = False
        try:
            Response = requests.post(
                f"{url or self.server_url}{extension}", 
                json = (EncryptedPostData), 
                verify=ensure_SSL      
            )
        except requests.exceptions.Timeout:
            return (True, {"status":"error", "timeout":True, "data":{       #special timeout error
                "script":__name__,
                "message":"VIPER_Server request has timed out.",
                "type":"request",
                "local":True,
                }
            })
        except requests.exceptions.RequestException as e:
            return (True, {"status":"error", "data":{
                "script":__name__,
                "message":f"VIPER_Server request error: {e}",
                "type":"request",
                "local":True,
                }
            })
        finally:
                if Response == False:
                    print("VIPER_Server request failed.")
                    return (True, {"status":"error", "data":{
                                "script":__name__,
                                "message":"VIPER_Server request failed.",
                                "type":"request",
                                "local":True,
                                }
                            })
                else:
                    if Response.status_code == 500:
                        ResponseFinal = {"status":"error", "data":{
                                            "script":__name__,
                                            "message":f"VIPER_Server ERROR code: {Response.status_code}",
                                            "type":"request",
                                            }
                                        }

                    else:
                        #anything other than 200, just state response code
                        ResponseFinal = {"status":"error", "data":{
                                            "script":__name__,
                                            "message":f"VIPER_Server response code: {Response.status_code}",
                                            "type":"request",
                                            }
                                        }
                    if  Response.status_code != 200:
                        ResponseFinal = {"status":"error", "data":{
                                                "script":__name__,
                                                "message":f"Server errror {Response.status_code}",
                                                "type":"data",
                                                "local":True,
                                                }
                                            }
                    else:
                        #response code = 200 = OK response
                        ResponseFinal = {"status":"error", "data":{
                                                "script":__name__,
                                                "message":"Decryption failed.",
                                                "type":"data",
                                                "local":True,
                                                }
                                            }
                        try:
                            ResponseFinal_raw = self.decrypt(Response.text)  
                            ResponseFinal = {"status":"error", "data":{
                                                "script":__name__,
                                                "message":"Response JSON loading error, but decryption successful.",
                                                "type":"data",
                                                "local":True,
                                                }
                                            }
                            ResponseFinal = json.loads(ResponseFinal_raw)
                        except:
                            0   
                return (ResponseFinal.get("status") != False, ResponseFinal)


    def get_public_key(self):
        """
        Returns the public key in coordinate format: tuple (x,y)
        """
        return self.session.get_public_key()
    

    def SHA256_hashify(self,string:bytes=None):
        return NotImplementedError("SHA256 Hashing has not been implemented in VIPER_ECC for micropython.")

    def derive_shared_secret(self, remote_public_coordinates):
        """
        Derives the shared secret using ECDH with the remote public key.
        """
        return self.session.derive_shared_secret(remote_public_coordinates)


    @staticmethod
    def derive_symmetric_key(shared_secret=None, info=b'handshake data'):
        return NotImplementedError("derive_symmetric_key has not been implemented in VIPER_ECC for micropython.")

    def flush_key_cache(self):
        self.key_cache = {}


    def encrypt_with_specified_private_key(self, plaintext:str, temp_private_key, remote_public_coordinates, mode="CBC"):  #ADDED MODE
        """
        Encrypts a message using the remote public key and derived symmetric key.
        """
        #warning, on micropython this will be horrifically slow
        return base64.b64encode( uECcrypto(temp_private_key).encrypt(plaintext,remote_public_coordinates,mode) )


    def encrypt(self, plaintext:str , remote_public_coordinates=None, mode="CBC"):
        """
        Encrypts a message using the remote public key and derived symmetric key.
        """
        return base64.b64encode( self.session.encrypt(plaintext=plaintext.encode('utf-8'),public_key=remote_public_coordinates, mode=mode) )

    def decrypt(self, ciphertext:str, remote_public_coordinates=None, mode="CBC"):
        """
        Decrypts a message using the remote public key and derived symmetric key.
        """
        return self.session.decrypt(ciphertext=base64.b64decode(ciphertext), public_key=remote_public_coordinates, mode=mode)
    

    def secure_connect_to_VIPER_Server(self, VIPER_Server_settings):
        return NotImplementedError("Secure connection protocol is not implemented yet. This feature will be added in the next version.")
