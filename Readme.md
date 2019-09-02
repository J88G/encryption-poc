# Encryption and Decryption POC

## Overview
This POC shows a simple way to encrypt and decrypt content in a safe way.
It's a nice solution when you need to transfer data between servers for example.

It uses a public-key to encrypt content and the private-key pair to decrypt it.


## How to Run it
On app.py you can find a simple example.
```
virtualenv -p python3.6 venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```
