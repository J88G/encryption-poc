import time
from encryption import Encryption
from decryption import Decryption

PUBLIC_KEY = 'master_keys/public-key.pem'
PRIVATE_KEY = 'master_keys/private-key.pem'
CONTENT = "Hello, my name is João"

print('Encrypt and Decrypt:\n"{}"\n'.format(CONTENT))
print('Key-pair:\n{}\n{}\n'.format(PUBLIC_KEY, PRIVATE_KEY))

START_ENCRYPTION = time.time()
encryption = Encryption(PUBLIC_KEY)
content_encrypted = encryption.encrypt(CONTENT)
END_ENCRYPTION = time.time() - START_ENCRYPTION

print("Content Encrypted:\n{}\n".format(content_encrypted))

START_DECRYPTION = time.time()
decryption = Decryption(PRIVATE_KEY)
content_decrypted = decryption.decrypt(content_encrypted)
print("Content Decrypted:\n{}\n".format(content_decrypted))

print("{:.4f} seconds to encrypt.\n{:.4f} seconds to decrypt.".format(END_ENCRYPTION, (
            time.time() - START_DECRYPTION)))
