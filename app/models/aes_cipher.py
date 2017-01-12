import binascii

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESCipher:
    def __init__(self, key, bs=16):
        self.__BS = bs
        #self.__iv = iv.encode()
        self.__key = key.encode()
        self.__cipher = Cipher(algorithms.AES(self.__key), modes.ECB(), backend=default_backend())

    def pad(self, s):
        BS = self.__BS
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, data):
        data_encode = data.encode()

        raw = self.pad(data_encode)
        enc = self.__cipher.encryptor().update(raw)

        return binascii.hexlify(enc).decode()

    def decrypt(self, data):
        enc = binascii.unhexlify(data)
        dec = self.__cipher.decryptor().update(enc)

        return self.unpad(dec).decode()

