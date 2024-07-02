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
        self.is_ca = 0

    def request_certificate(self, ca, hours_limit=1):
        self.certificate, self.valid_from, self.valid_to = ca.sign_certificate(self.public_key, hours_limit=hours_limit, ca=ca)

    def request_cs_authority(self, ca):
        self.is_ca = ca.grant_request_ca_authority()
        return self.is_ca

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

    def sign_certificate(self, entity_public_key, hours_limit=1, ca=None):
        if (ca.is_ca):
            valid_from = datetime.datetime.now()
            valid_to = valid_from + datetime.timedelta(hours=hours_limit)
            valid_from_str = valid_from.strftime('%Y-%m-%d %H:%M:%S')
            valid_to_str = valid_to.strftime('%Y-%m-%d %H:%M:%S')
            certificate_data = entity_public_key.export_key() + valid_from_str.encode('utf-8') + valid_to_str.encode(
                'utf-8')
            certificate_hash = SHA256.new(certificate_data)
            signature = pkcs1_15.new(self.key).sign(certificate_hash)
            return signature, valid_from_str, valid_to_str
        else:
            return False, False, False
