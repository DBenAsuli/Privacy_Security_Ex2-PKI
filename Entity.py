# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

from CA import *


class Entity:
    def __init__(self, name=None):
        if name == None:
            self.name = generate_random_string(4)
        self.key = RSA.generate(2048)
        self.public_key = self.key.publickey()
        self.certificate = None
        self.valid_from = None
        self.valid_to = None
        self.is_ca = 0

    # Requesting a certificate from CA.
    # The user can specify the validity period of the certificate, default is 1 hour.
    # User also specify which CA it requests the certificate from- either an external
    # one or the entity itself.
    def request_certificate(self, ca, hours_limit=1):
        self.certificate, self.valid_from, self.valid_to = ca.sign_certificate(entity_public_key=self.public_key,
                                                                               entity_name=self.name,
                                                                               hours_limit=hours_limit, ca=ca)

    # The entity signs the data for authenticity
    def sign_data(self, data):
        # If it doesnt have a proper certificate, it will not be able to sign the data.
        if not self.certificate:
            raise ValueError("Entity does not have a valid certificate.")

        # If it has a certificate, it uses it's provate key to sign the data
        data_hash = SHA256.new(data.encode('utf-8'))
        signature = pkcs1_15.new(self.key).sign(data_hash)
        return base64.b64encode(signature).decode('utf-8')

    # The entity encrypts the data for verification of Data Integrity.
    def encrypt_data(self, data, recipient_public_key):
        cipher = PKCS1_OAEP.new(recipient_public_key)
        encrypted_data = cipher.encrypt(data.encode('utf-8'))
        return base64.b64encode(encrypted_data).decode('utf-8')

    # Requesting an authority from CA to become its own CA.
    # Normally, the decision is done randomly.
    # If 'force_value' flag is passed, the request returns the 'forced_value'.
    def request_cs_authority(self, ca, force_value=0, forced_value=0):
        self.is_ca = ca.grant_request_ca_authority(force_value, forced_value)
        return self.is_ca

    # If the Entity was made a CA, it can sign a certificate by itself.
    # Else, this function returns nothing ('False' x3)
    def sign_certificate(self, entity_public_key, entity_name, hours_limit=1, ca=None):
        if (ca.is_ca):
            # Calculates validity period
            valid_from = datetime.datetime.now()
            valid_to = valid_from + datetime.timedelta(hours=hours_limit)
            valid_from_str = valid_from.strftime('%Y-%m-%d %H:%M:%S')
            valid_to_str = valid_to.strftime('%Y-%m-%d %H:%M:%S')

            # Concatenate the key, the data and the valid timestamp to the signed string
            certificate_data = self.name.encode('utf-8') + entity_name.encode(
                'utf-8') + entity_public_key.export_key() + valid_from_str.encode(
                'utf-8') + valid_to_str.encode('utf-8')

            # Creates signature
            certificate_hash = SHA256.new(certificate_data)
            signature = pkcs1_15.new(self.key).sign(certificate_hash)
            return signature, valid_from_str, valid_to_str
        else:
            # Entity doesn't have authority to sign
            return False, False, False

    # If the Entity was made a CA, it can also turn another entity to CA.
    # Else, this function returns 0 (non-grant)
    def grant_request_ca_authority(self, force_value=0, forced_value=0):
        if not (self.is_ca):
            return 0

        if force_value:
            return forced_value

        return random.randint(0, 1)
