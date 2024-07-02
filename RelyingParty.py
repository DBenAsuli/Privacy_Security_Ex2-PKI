# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

from Entity import *

class RelyingParty:
    def __init__(self, public_key, entity):
        self.public_key = public_key
        self.entity = entity


    def verify_signed_data(self, entity, data, signature):
        if not self.verify_certificate(entity.public_key, entity.certificate, entity.valid_from, entity.valid_to):
            return False
        data_hash = SHA256.new(data.encode('utf-8'))
        signature = base64.b64decode(signature.encode('utf-8'))
        try:
            pkcs1_15.new(entity.public_key).verify(data_hash, signature)
            return True
        except (ValueError, TypeError):
            return False

    def decrypt_data(self, encrypted_data, private_key):
        cipher = PKCS1_OAEP.new(private_key)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data.encode('utf-8')))
        return decrypted_data.decode('utf-8')

    def verify_certificate(self, entity_public_key, signature, valid_from, valid_to):
        certificate_data = entity_public_key.export_key() + valid_from.encode('utf-8') + valid_to.encode('utf-8')
        certificate_hash = SHA256.new(certificate_data)
        try:
            pkcs1_15.new(self.public_key).verify(certificate_hash, signature)
            current_datetime = datetime.datetime.now()
            valid_from_dt = datetime.datetime.strptime(valid_from, '%Y-%m-%d %H:%M:%S')
            valid_to_dt = datetime.datetime.strptime(valid_to, '%Y-%m-%d %H:%M:%S')
            if valid_from_dt <= current_datetime <= valid_to_dt:
                return True
            return False
        except (ValueError, TypeError):
            return False