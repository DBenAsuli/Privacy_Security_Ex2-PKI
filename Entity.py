# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

from CA import *


class Entity:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.certificate = None
        self.valid_from = None
        self.valid_to = None

    def request_certificate(self, ca):
        self.certificate, self.valid_from, self.valid_to = ca.sign_certificate(self.public_key)

    def sign_data(self, data):
        if not self.certificate:
            raise ValueError("Entity does not have a valid certificate.")
        data_hash = SHA256.new(data.encode('utf-8'))
        signature = pkcs1_15.new(self.key).sign(data_hash)
        return base64.b64encode(signature).decode('utf-8')

    def encrypt_data(self, data, recipient_public_key):
        cipher = PKCS1_OAEP.new(recipient_public_key)
        encrypted_data = cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted_data).decode('utf-8')