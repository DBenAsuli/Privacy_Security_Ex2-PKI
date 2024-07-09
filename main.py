# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

from test import *

if __name__ == '__main__':
    ca = CA()
    entity = Entity()
    relying_party = RelyingParty()

    # Entity requests a certificate from the CA
    entity.request_certificate(ca=ca)

    # Entity signs some data
    data = generate_random_string(random.randint(1, 100))
    encrypted_data = entity.encrypt_data(data=data, recipient_public_key=relying_party.public_key)
    signature = entity.sign_data(data=encrypted_data)

    # Relying Party verifies the signed data
    is_verified = relying_party.verify_signed_data(entity=entity, ca=ca, data=encrypted_data, signature=signature)
    decrypted_data = relying_party.decrypt_data(encrypted_data=encrypted_data)

    if not is_verified:
        print("\nAuthenticity verification failed")
        if decrypted_data != data:
            print("\nData Integrity verification also failed")
    elif decrypted_data != data:
        print("\nData Integrity verification failed")

    relying_party = RelyingParty()

    ca1 = CA()
    entity1 = Entity()
    entity2 = Entity()
    ca2 = CA()
    entity3 = Entity()

    entity1.request_certificate(ca=ca1)
    entity2.request_certificate(ca=ca1)
    entity3.request_certificate(ca=ca2)

    # Entities signs some data
    data1 = generate_random_string(random.randint(1, 100))
    signature1 = entity1.sign_data(data1)
    data2 = generate_random_string(random.randint(1, 100))
    signature2 = entity2.sign_data(data2)
    data3 = generate_random_string(random.randint(1, 100))
    signature3 = entity3.sign_data(data3)

    is_verified1 = relying_party.verify_signed_data(entity=entity1, ca=ca1, data=data1, signature=signature1)
    is_verified2 = relying_party.verify_signed_data(entity=entity2, ca=ca1, data=data2, signature=signature2)
    is_verified3 = relying_party.verify_signed_data(entity=entity3, ca=ca2, data=data3, signature=signature3)

    if not is_verified1:
        error = 1
        print("\nVerification for test " + str(i) + " failed")
        print("\nFailed to verify first entity inside the Relying Party")
    elif not is_verified2:
        error = 1
        print("\nVerification for test " + str(i) + " failed")
        print("\nFailed to verify second entity inside the Relying Party")
    elif not is_verified3:
        error = 1
        print("\nVerification for test " + str(i) + " failed")
        print("\nFailed to verify third entity (from different CA) inside the Relying Party")
    else:
        print("SUCCESS!")
