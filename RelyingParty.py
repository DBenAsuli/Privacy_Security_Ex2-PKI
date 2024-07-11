# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

from Entity import *

class RelyingParty:
    def __init__(self):
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        pass

    # Once receiving signed data from entity, verify its authenticity
    def verify_signed_data(self, entity, ca, data, signature):
        # First verify the validity of the Entity's certificate
        if not self.verify_certificate(entity_public_key=entity.public_key, ca_public_key=ca.public_key,
                                       entity_name=entity.name, ca_name=ca.name, ca=ca,
                                       signature=entity.certificate, valid_from=entity.valid_from,
                                       valid_to=entity.valid_to):
            return False

        # If it has a valid certificate,
        # Check authenticity of the data signed by the entity
        data_hash = SHA256.new(data.encode('utf-8'))
        signature = base64.b64decode(signature.encode('utf-8'))
        try:
            pkcs1_15.new(entity.public_key).verify(data_hash, signature)
            return True
        except (ValueError, TypeError):
            return False

    # Verify the validity of the Entity's certificate
    def verify_certificate(self, entity_public_key, ca_public_key, ca_name, ca, entity_name, signature, valid_from,
                           valid_to):

        # Verify the signature was not revoked by CA
        if not ca.verify_signature_validity(entity_name=entity_name, signature=signature):
            return False

        # Concatenate the key, the data and the valid timestamp to the signed string
        certificate_data = ca_name.encode('utf-8') + entity_name.encode(
            'utf-8') + entity_public_key.export_key() + valid_from.encode('utf-8') + valid_to.encode('utf-8')
        certificate_hash = SHA256.new(certificate_data)
        try:
            # Verify the certificate itself based on the string's hash
            pkcs1_15.new(ca_public_key).verify(certificate_hash, signature)

            # Verify timestamp validity
            current_datetime = datetime.datetime.now()
            valid_from_dt = datetime.datetime.strptime(valid_from, '%Y-%m-%d %H:%M:%S')
            valid_to_dt = datetime.datetime.strptime(valid_to, '%Y-%m-%d %H:%M:%S')
            if valid_from_dt <= current_datetime <= valid_to_dt:
                return True
            else:
                return False

        except (ValueError, TypeError):
            # Some error occured during verification, the certificate is not valid
            print("Verification failed")
            return False

    # The party decrypts the data for verification of Data Integrity.
    def decrypt_data(self, encrypted_data):
        cipher = PKCS1_OAEP.new(self.key)
        decrypted_data = cipher.decrypt(base64.b64decode(encrypted_data.encode('utf-8')))
        return decrypted_data.decode('utf-8')

    def request_certificate_revokation(self, ca, entity_name, signature):
        ca.revoke_certificate(entity_name=entity_name, signature=signature)
