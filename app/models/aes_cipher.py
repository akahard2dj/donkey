import binascii
from Crypto.Cipher import AES

#from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#from cryptography.hazmat.backends import default_backend


class AESCipher:
    def __init__(self, key, bs=16):
        self.__BS = bs
        #self.__iv = iv.encode()
        self.__key = key
        #self.__cipher = Cipher(algorithms.AES(self.__key), modes.CBC(self.__iv), backend=default_backend())

    def pad(self, s):
        BS = self.__BS
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, data):

        data_enc = data.encode()
        raw = self.pad(data_enc)
        cipher = AES.new(self.__key)
        enc = cipher.encrypt(raw)

        return binascii.hexlify(enc).decode()
        '''
        data_encode = data.encode()

        raw = self.pad(data_encode)
        enc = self.__cipher.encryptor().update(raw)

        return binascii.hexlify(enc).decode()
        '''

    def decrypt(self, data):

        enc = binascii.unhexlify(data)
        cipher = AES.new(self.__key)
        dec = cipher.decrypt(enc)

        return self.unpad(dec).decode()
        '''
        enc = binascii.unhexlify(data)
        dec = self.__cipher.decryptor().update(enc)

        return self.unpad(dec).decode()
        '''
