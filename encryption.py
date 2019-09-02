"""Encryption"""
import base64
import random
import string

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_public_key


def _get_random_secret():
    """
    Returns a 16 characters random string (ascii_lowercase + digits)
    :return: secret
    """
    secret = ''.join([random.choice(string.ascii_lowercase + string.digits) for n in range(16)])
    return secret


def _encrypt_message(secret, plain_text, encode=True):
    """
    Receives a secret and a plain text to encrypt
    Return message encrypted with AES where key is the secret
    :param secret: string
    :param plain_text: the text to be encrypted
    :param encode: encoded the data on return
    :return: encrypted message
    """
    key = SHA256.new(secret).digest()
    random_initialization_vector = Random.new().read(AES.block_size)
    encryptor = AES.new(key, AES.MODE_CBC, random_initialization_vector)
    aes_padding = AES.block_size - len(plain_text) % AES.block_size
    plain_text += bytes([aes_padding]) * aes_padding
    data = random_initialization_vector + encryptor.encrypt(plain_text)
    return base64.b64encode(data).decode("utf-8") if encode else data


def _encrypt_secret(secret, public_key):
    """
    Receive a secret and a public-key and encrypts the secret using that public_key
    :param secret: string
    :param public_key: the public_key path
    :return: encrypted secret
    """
    cipher_secret_bytes = public_key.encrypt(secret.encode('utf-8'),
                                             padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()), # pylint: disable=line-too-long
                                                          algorithm=hashes.SHA512(), label=None))
    cipher_secret = base64.urlsafe_b64encode(cipher_secret_bytes)
    return cipher_secret


def _get_public_key(path):
    """
    Give access of the content of public-key
    :param path: path of the public-key
    :return: public-key content
    """
    with open(path, 'r') as _public_key_file:
        public_key = _public_key_file.read()
        b64data_public_key = '\n'.join(public_key.splitlines()[1:-1])
        derdata_public_key = base64.b64decode(b64data_public_key)
        public_key = load_der_public_key(derdata_public_key, default_backend())
    return public_key


class Encryption:  # pylint: disable=too-few-public-methods
    """ Encryption handling AES encryption with RSA protected secret """
    def __init__(self, public_key_path):
        self.public_key = _get_public_key(public_key_path)

    def encrypt(self, text):
        """
        Encrypts text using AES encryption.
        The secret is secured using RSA and stored alongside the encrypted blob
        :param text: string. Text to be encrypted
        :return: encrypted secret + encrypted message
        """
        secret = _get_random_secret()
        encrypted_secret = _encrypt_secret(secret, self.public_key)
        encrypted_message = _encrypt_message(secret.encode(), text.encode())
        return encrypted_secret.decode() + encrypted_message
