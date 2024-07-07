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

    # Request from CA to sign the certificate using the entity's public key
    # Calculated a timestamp that makes the signature valid for 'hours_limit' hours.
    def sign_certificate(self, entity_public_key, hours_limit=1, ca=None):
        # Calculates validity period
        valid_from = datetime.datetime.now()
        valid_to = valid_from + datetime.timedelta(hours=hours_limit)
        valid_from_str = valid_from.strftime('%Y-%m-%d %H:%M:%S')
        valid_to_str = valid_to.strftime('%Y-%m-%d %H:%M:%S')

        # Concatenate the key, the data and the valid timestamp to the signed string
        certificate_data = entity_public_key.export_key() + valid_from_str.encode('utf-8') + valid_to_str.encode(
            'utf-8')

        # Creates signature
        certificate_hash = SHA256.new(certificate_data)
        signature = pkcs1_15.new(self.key).sign(certificate_hash)
        return signature, valid_from_str, valid_to_str

    # An entity requests the CA to make it its own CA.
    # Normally, the decision is done randomly.
    # If 'force_value' flag is passed, the request returns the 'forced_value'.
    def grant_request_ca_authority(self, force_value=0, forced_value=0):
        if force_value:
            return forced_value

        return random.randint(0, 1)

