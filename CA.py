# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

import base64
import random
import datetime
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15


class CA:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.is_ca = 1

    def sign_certificate(self, entity_public_key, hours_limit=1, ca=None):
        valid_from = datetime.datetime.now()
        valid_to = valid_from + datetime.timedelta(hours=hours_limit)
        valid_from_str = valid_from.strftime('%Y-%m-%d %H:%M:%S')
        valid_to_str = valid_to.strftime('%Y-%m-%d %H:%M:%S')
        certificate_data = entity_public_key.export_key() + valid_from_str.encode('utf-8') + valid_to_str.encode(
            'utf-8')
        certificate_hash = SHA256.new(certificate_data)
        signature = pkcs1_15.new(self.key).sign(certificate_hash)
        return signature, valid_from_str, valid_to_str

    def grant_request_ca_authority(self):
        return random.randint(0, 1)

