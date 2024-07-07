# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

from test import *

if __name__ == '__main__':
    ca = CA()
    entity = Entity()
    relying_party = RelyingParty(public_key=ca.public_key, entity=entity)

    # Entity requests a certificate from the CA
    entity.request_certificate(ca=ca)

    # Entity signs some data
    data = generate_random_string(random.randint(1, 100))
    encrypted_data = entity.encrypt_data(data, entity.public_key)
    signature = entity.sign_data(encrypted_data)

    # Relying Party verifies the signed data
    is_verified = relying_party.verify_signed_data(entity, encrypted_data, signature)
    decrypted_data = relying_party.decrypt_data(encrypted_data, entity.key)

    if not is_verified:
        print("\nAuthenticity verification failed")
        if decrypted_data != data:
            print("\nData Integrity verification also failed")
    elif decrypted_data != data:
        print("\nData Integrity verification failed")
    else:
        print("SUCCESS!")

