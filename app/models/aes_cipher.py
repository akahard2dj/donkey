import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AESCipher:
    def __init__(self, key, iv, bs=16):
        self.__BS = bs
        self.__key = key.encode()
        self.__iv = iv.encode()
        self.__cipher = Cipher(algorithms.AES(self.__key), modes.CBC(self.__iv), backend=default_backend())

    def pad(self, s):
        BS = self.__BS
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode()

    @staticmethod
    def unpad(s):
        return s[:-ord(s[len(s)-1:])]

    def encrypt(self, data):
        encryptor = self.__cipher.encryptor()
        data_enc = data.encode()
        raw = self.pad(data_enc)
        enc = encryptor.update(raw)

        return binascii.hexlify(enc).decode()

    def decrypt(self, data):
        decryptor = self.__cipher.decryptor()
        enc = binascii.unhexlify(data)
        dec = decryptor.update(enc)

        return self.unpad(dec).decode()
