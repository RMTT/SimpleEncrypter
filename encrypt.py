from base64 import b64encode, b64decode
from config import *
from Crypto.Cipher import DES, DES3, AES, Salsa20,ChaCha20
import random
import json


class Encrypter:

    def __init__(self):
        self.cipher = {
            0: self.__des,
            1: self.__des3,
            2: self.__aes,
            3: self.__salsa20,
            4: self.__chacha20
        }

        self.cipher_d = {
            0: self.__des_decrypt,
            1: self.__des3_decrypt,
            2: self.__aes_decrypt,
            3: self.__salsa20_decrypt,
            4: self.__chacha20_decrypt
        }

    def __des(self, message: bytes):
        cipher = DES.new(DES_KEY, DES.MODE_OFB)
        ct_bytes = cipher.encrypt(message)
        iv = b64encode(cipher.iv).decode(DEFAULT_ENCODING)
        ct = b64encode(ct_bytes).decode(DEFAULT_ENCODING)
        result = {"iv": iv, "cipher": ct}
        return b64encode(bytes(json.dumps(result), encoding=DEFAULT_ENCODING))

    def __des_decrypt(self, message: bytes):
        text = b64decode(message)
        j = json.loads(text)
        iv = b64decode(j['iv'])
        ct = b64decode(j['cipher'])
        cipher = DES.new(DES_KEY, DES.MODE_OFB, iv=iv)

        pt = cipher.decrypt(ct)
        return pt

    def __des3(self, message: bytes):
        cipher = DES3.new(DES3_KEY, DES3.MODE_OFB)
        ct_bytes = cipher.encrypt(message)
        iv = b64encode(cipher.iv).decode(DEFAULT_ENCODING)
        ct = b64encode(ct_bytes).decode(DEFAULT_ENCODING)
        result = {"iv": iv, "cipher": ct}
        return b64encode(bytes(json.dumps(result), encoding=DEFAULT_ENCODING))

    def __des3_decrypt(self, message: bytes):
        text = b64decode(message)
        j = json.loads(text)
        iv = b64decode(j['iv'])
        ct = b64decode(j['cipher'])

        cipher = DES3.new(DES3_KEY, DES3.MODE_OFB, iv=iv)

        pt = cipher.decrypt(ct)
        return pt

    def __aes(self, message: bytes):
        cipher = AES.new(AES_KEY, AES.MODE_OFB)
        ct_bytes = cipher.encrypt(message)
        iv = b64encode(cipher.iv).decode(DEFAULT_ENCODING)
        ct = b64encode(ct_bytes).decode(DEFAULT_ENCODING)
        result = {"iv": iv, "cipher": ct}
        return b64encode(bytes(json.dumps(result), encoding=DEFAULT_ENCODING))

    def __aes_decrypt(self, message: bytes):
        text = b64decode(message)
        j = json.loads(text)
        iv = b64decode(j['iv'])
        ct = b64decode(j['cipher'])

        cipher = AES.new(AES_KEY, AES.MODE_OFB, iv=iv)

        pt = cipher.decrypt(ct)
        return pt

    def __salsa20(self, message: bytes):
        cipher = Salsa20.new(SALSA20_KEY)
        ct_bytes = cipher.encrypt(message)
        nonce = b64encode(cipher.nonce).decode(DEFAULT_ENCODING)
        ct = b64encode(ct_bytes).decode(DEFAULT_ENCODING)
        result = {"nonce": nonce, "cipher": ct}
        return b64encode(bytes(json.dumps(result), encoding=DEFAULT_ENCODING))

    def __salsa20_decrypt(self, message: bytes):
        text = b64decode(message)
        j = json.loads(text)
        nonce = b64decode(j['nonce'])
        ct = b64decode(j['cipher'])

        cipher = Salsa20.new(SALSA20_KEY, nonce=nonce)
        pt = cipher.decrypt(ct)
        return pt


    def __chacha20(self, message: bytes):
        cipher = ChaCha20.new(key=CHACHA20_KEY)
        ct_bytes = cipher.encrypt(message)
        nonce = b64encode(cipher.nonce).decode(DEFAULT_ENCODING)
        ct = b64encode(ct_bytes).decode(DEFAULT_ENCODING)
        result = {"nonce": nonce, "cipher": ct}
        return b64encode(bytes(json.dumps(result), encoding=DEFAULT_ENCODING))

    def __chacha20_decrypt(self, message: bytes):
        text = b64decode(message)
        j = json.loads(text)
        nonce = b64decode(j['nonce'])
        ct = b64decode(j['cipher'])

        cipher = ChaCha20.new(key=CHACHA20_KEY, nonce=nonce)
        pt = cipher.decrypt(ct)
        return pt

    def encrypt(self, message: bytes):
        length = len(message)
        index = 0

        cipher_text = b','
        cipher_list = []
        id = 0
        while (index < length):
            text = message[index:index + INTERVAL]
            which = random.randint(0, MAX_CIPHERS - 1)
            cipher_list.append(self.cipher[which](text))
            id = MAX_CIPHERS * id + which
            index = index + INTERVAL
        cipher_text = cipher_text.join(cipher_list)
        return id, b64encode(cipher_text)

    def decrypt(self, message: bytes, id: int):
        text = str(b64decode(message),encoding=DEFAULT_ENCODING)
        l = text.split(',')
        length = len(l)

        cipher_order = []

        i = 0
        while i < length:
            cipher_order.append(id % MAX_CIPHERS)
            id = int(id / MAX_CIPHERS)
            i += 1

        pt = b''
        index = 0
        while index < length:
            pt += self.cipher_d[cipher_order[length - index - 1]](l[index])
            index += 1
        return pt
