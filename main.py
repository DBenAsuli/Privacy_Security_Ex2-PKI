# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

from RelyingParty import *

if __name__ == '__main__':
    ca = CA()
    entity = Entity()
    relying_party = RelyingParty(public_key=ca.public_key, entity=entity)

    # Entity requests a certificate from the CA with a validity duration of 10 hours
    entity.request_certificate(ca=ca)

    # Entity signs some data
    data = "This is a secret message."
    signature = entity.sign_data(data)

    # Relying Party verifies the signed data
    is_verified = relying_party.verify_signed_data(entity, data, signature)
    print(f"Data verification status: {is_verified}")

    # Encrypt and decrypt data
    recipient = Entity()
    recipient.request_certificate(ca=ca)

    encrypted_data = entity.encrypt_data(data, recipient.public_key)
    decrypted_data = relying_party.decrypt_data(encrypted_data, recipient.key)
    print(f"Decrypted data: {decrypted_data}")
