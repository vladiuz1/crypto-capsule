import os
import gc
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from .mnemonic import Mnemonic

gc.enable()


class Salt:

    def __init__(self, salt_bytes: bytes = None):
        self._salt = salt_bytes

    def to_mnemonic(self):
        return Mnemonic('en').mnemonic_encode(int.from_bytes(self._salt, "big"))

    @classmethod
    def generate(cls):
        return cls(os.urandom(16))

    @classmethod
    def from_mnemonic(cls, mnem):
        d = Mnemonic('en').mnemonic_decode(mnem)
        return cls(d.to_bytes((d.bit_length() + 7) // 8, "big"))

    def __bytes__(self):
        return self._salt

    __str__ = to_mnemonic

    __repr__ = to_mnemonic


DEFAULT_SALT = Salt.from_mnemonic('name that can open this door into that little close alley between')

# From two different six-word sequences matching english wordlist from this book:
# Title: The Adventures of Tom Sawyer
# Author: Mark Twain (Samuel Clemens)

# Normally you would want to use a different salt for each key/msg, otherwise its not a secret

class Key:
    """
    Very basic key class.
    All you can do is generate a key with it.
    """

    def __init__(self, key_bytes: bytes = None):
        self._key = key_bytes
    @classmethod
    def generate(cls):
        return cls(base64.urlsafe_b64decode(Fernet.generate_key()))

    @classmethod
    def from_password(cls, password: bytes, salt: Salt = DEFAULT_SALT, iterations: int = 1500000):
        pbkdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=bytes(salt),
            iterations=iterations,
        )
        return cls(pbkdf.derive(password))

    @classmethod
    def from_mnemonic(cls, mnem):
        d = Mnemonic('en').mnemonic_decode(mnem)
        return cls(d.to_bytes((d.bit_length() + 7) // 8, "big"))

    def to_mnemonic(self):
        return Mnemonic('en').mnemonic_encode(int.from_bytes(self._key, "big"))

    @classmethod
    def from_hex(cls, key_hex):
        return cls(bytes.fromhex(key_hex))

    def to_hex(self):
        return self._key.hex()


    def encrypt(self, message: bytes):
        return base64.urlsafe_b64decode(Fernet(base64.urlsafe_b64encode(self._key)).encrypt(message))

    def decrypt(self, cypher_text: bytes):
        return Fernet(base64.urlsafe_b64encode(self._key)).decrypt(base64.urlsafe_b64encode(cypher_text))

    def __bytes__(self):
        return self._key

    __str__ = to_mnemonic

class Capsule():
    """
    A convenience class that represents an encrypted bytes object.

    Usage:

    from crypt_capsule import Capsule, Key
    key = Key.generate()
    capsule = Capsule.create(key, 'Some text'.encode('utf-8'))
    """
    def open(self, key: Key) -> bytes:
        """
        Decrypt capsule and return the encrypted data.

        :param key: Key that will be used to decrypt the contents
        :return: the decrypted data (bytes)
        """
        data = key.decrypt(self._cipher_text)
        self._id = hashlib.sha1(data).hexdigest()[:10]
        return data

    @classmethod
    def create(cls, key: Key, data: bytes):
        """
        Create an encrypted capsule, and return and instance of the Capsule object
        :param key: key to encrypt with
        :param data: bytes object to encapsulate
        :return: instance of Capsule object
        """
        self = cls()
        self._cipher_text = key.encrypt(data)
        self._id = hashlib.sha1(data).hexdigest()[:10]
        return self

    def cipherText(self) -> bytes:
        return self._cipher_text

    def id(self) -> str:
        """
        Return deterministic ID of the capsule based on encrypted text.
        :return:
        """
        return self._id

    def nuke(self):
        """
        Destroy the contents of the capsule object
        """
    def to_mnemonic(self, lang='en') -> str:
        source = bytes.fromhex(self._id) + self._cipher_text
        return Mnemonic(lang).mnemonic_encode(int.from_bytes(source, "big"))

    @classmethod
    def from_mnemonic(cls, mnem, lang = 'en'):
        """
        Create a capsule instance from mnemonic

        :param mnem: the mnemonic
        :param lang: default 'en'
        :return: instance of capsule object
        """
        d = Mnemonic(lang).mnemonic_decode(mnem)
        self = cls()
        from_mnem = d.to_bytes((d.bit_length() + 7) // 8, "big")
        self._cipher_text = from_mnem[5:]
        self._id = from_mnem[:5].hex()
        return self

    __str__ = to_mnemonic

    __repr__ = to_mnemonic
