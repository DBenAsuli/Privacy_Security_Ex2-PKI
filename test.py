# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

import string
from RelyingParty import *


def generate_random_string(length):
    letters = string.ascii_letters + string.digits  # includes both uppercase, lowercase letters, and digits
    result_str = ''.join(random.choice(letters) for _ in range(length))
    return result_str


if __name__ == '__main__':
    num_of_tests = 100
    error = 0

    print("Starting test")

    for i in range(num_of_tests):
        ca = CA()
        entity = Entity()
        relying_party = RelyingParty(public_key=ca.public_key, entity=entity)
        time_expired = random.randint(0, 1)
        sabotage_signature = random.randint(0, 1)
        sabotage_data = random.randint(0, 1)
        become_ca = random.randint(0, 1)
       # become_ca = 1

        # Entity requests a certificate from the CA
        if time_expired:
            entity.request_certificate(ca=ca, hours_limit=0)
        else:
            entity.request_certificate(ca=ca)

        # Entity signs some data
        data = generate_random_string(random.randint(1, 100))

        if not sabotage_signature:
            signature = entity.sign_data(data)
        else:
            signature = "XOXO"

        # Relying Party verifies the signed data
        is_verified = relying_party.verify_signed_data(entity, data, signature)

        if not is_verified and not time_expired and not sabotage_signature:
            error = 1
            print("Verification for test " + str(i) + " failed")
            break
        if is_verified and (time_expired or sabotage_signature):
            error = 1
            print("Verification for test " + str(i) + " failed, " + "time_expired = " + str(
                time_expired) + ", sabotage_signature =" + str(sabotage_signature))
            break

        # Encrypt and decrypt data
        recipient = Entity()
        recipient.request_certificate(ca=ca)

        if not sabotage_data:
            encrypted_data = entity.encrypt_data(data, recipient.public_key)
        else:
            encrypted_data = entity.encrypt_data("XXXX", recipient.public_key)

        decrypted_data = relying_party.decrypt_data(encrypted_data, recipient.key)

        if not sabotage_data:
            if decrypted_data != data:
                error = 1
                print("Decryption for test " + str(i) + " failed")
                break
        if sabotage_data:
            if decrypted_data == data:
                error = 1
                print("Decryption for test " + str(i) + " failed, after sabotagin data")
                break

        become_ca = entity.request_cs_authority(ca=ca)

        if become_ca:
            entity2 = Entity()

            relying_party = RelyingParty(public_key=entity.public_key, entity=entity2)
            time_expired = random.randint(0, 1)
            sabotage_signature = random.randint(0, 1)
            sabotage_data = random.randint(0, 1)

            # New Entity requests a certificate from the new CA, which is previous entity
            if time_expired:
                entity2.request_certificate(ca=entity, hours_limit=0)
            else:
                entity2.request_certificate(ca=entity)

            # Entity signs some data
            data = generate_random_string(random.randint(1, 100))

            if not sabotage_signature:
                signature = entity2.sign_data(data)
            else:
                signature = "XOXO"

            # Relying Party verifies the signed data
            is_verified = relying_party.verify_signed_data(entity2, data, signature)

            if not is_verified and not time_expired and not sabotage_signature:
                error = 1
                print("Verification for test " + str(i) + " failed")
                break
            if is_verified and (time_expired or sabotage_signature):
                error = 1
                print("Verification for test " + str(i) + " failed, " + "time_expired = " + str(
                    time_expired) + ", sabotage_signature =" + str(sabotage_signature))
                break

        else:
            entity2 = Entity()

            # New Enitity trying to request certificate from old Entity,
            # Which is not a CA
            relying_party = RelyingParty(public_key=entity.public_key, entity=entity2)
            entity2.request_certificate(ca=entity)

            if not (entity2.certificate == False):
                error = 1
                print("Entity acted as CA without permission")
                break




    if error == 0:
        print("All tests PASSED")
    else:
        print("Some test FAILED")
