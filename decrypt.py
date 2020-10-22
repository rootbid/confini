import base64
import os
import configparser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

C_KEY = os.environ.get("C_KEY")
C_NOUNCE = os.environ.get("C_NOUNCE")

# key = base64.decodebytes(b'NvDy+u51EfMC+amJzoJO+w==')
# nonce = base64.decodebytes(b'd5+SLyfPGUSeug50nK1WGA==')
# ct = base64.decodebytse(b'vTVxjyUms4Z4jex/OcMcQlY=')

key = base64.decodebytes(C_KEY.encode('utf-8'))
nonce = base64.decodebytes(C_NOUNCE.encode('utf-8'))

config = configparser.ConfigParser()
config.read('C:\\DataSources\\conf.ini')
section = "Test"
encrypted_password = base64.decodebytes(config[section]['password'].encode('utf-8'))
backend = default_backend()
cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=backend)
decryptor = cipher.decryptor()
print((decryptor.update(encrypted_password) + decryptor.finalize()).decode('utf-8'))