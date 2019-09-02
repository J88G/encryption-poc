"""Decryption"""
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_der_private_key
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from exceptions import DecryptionException


def _decrypt_secret(cipher_text, private_key):
    """
    Decrypts AES secret using the RSA private_key
    :param cipher_text: the encrypted secret
    :param private_key: path of private-key
    :return: secret decrypted
    """
    decrypted_bytes = private_key.decrypt(base64.urlsafe_b64decode(cipher_text),
                                          padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA512()),
                                                       algorithm=hashes.SHA512(), label=None))
    decrypted_cipher_text = decrypted_bytes.decode('utf-8')
    return decrypted_cipher_text


def _decrypt_message(secret, source, decode=True):
    """
    Decrypts message using the AES secret
    :param secret: decrypted secret
    :param source: encrypted message
    :param decode:
    :return: decrypted message
    """
    if decode:
        source = base64.b64decode(source.encode("utf-8"))
    secret = SHA256.new(secret).digest()
    initialization_vector = source[:AES.block_size]
    decryptor = AES.new(secret, AES.MODE_CBC, initialization_vector)
    data = decryptor.decrypt(source[AES.block_size:])
    aes_padding = data[-1]
    if data[-aes_padding:] != bytes([aes_padding]) * aes_padding:
        raise ValueError("Invalid padding...")
    return data[:-aes_padding]


def _get_private_key(path):
    """
    Opens private key file and return it's content
    :param path: private-key path
    :return:
    """
    with open(path, 'r') as _private_key_file:
        _private_key = _private_key_file.read()
        b64data_private_key = '\n\n\n\n\n'.join(_private_key.splitlines()[1:-1])
        derdata_private_key = base64.b64decode(b64data_private_key)
        private_key = load_der_private_key(derdata_private_key, None, default_backend())
    return private_key


class Decryption:  # pylint: disable=too-few-public-methods
    """ Encryption handling AES decryption with RSA protected secret """
    def __init__(self, private_key_path):
        self.private_key = _get_private_key(private_key_path)

    def decrypt(self, encrypted_text):
        """
        Decrypts text using AES encryption.
        The AES secret is secured using RSA and stored alongside the encrypted blob
        :param encrypted_text: the text to be parsed
        :return: the decrypted message
        """
        try:
            message_encrypted = encrypted_text[344:]
            secret_encrypted = encrypted_text[:344]
            secret_decrypted = _decrypt_secret(secret_encrypted.encode(), self.private_key)
            message_decrypted = _decrypt_message(secret_decrypted.encode(), message_encrypted)
        except ValueError:
            raise DecryptionException()

        return message_decrypted.decode()
