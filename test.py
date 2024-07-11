# Advanced Topics in Online Privacy and Cybersecurity     Exercise 2
# Dvir Ben Asuli                                          318208816
# The Hebrew University of Jerusalem                      July 2024

import re

from RelyingParty import *

if __name__ == '__main__':
    num_of_tests = random.randint(0, 500)
    error = 0

    print("Starting " + str(num_of_tests) + " tests:")

    for i in range(num_of_tests):
        ca = CA()
        entity = Entity()
        relying_party = RelyingParty()
        time_expired = random.randint(0, 1)
        sabotage_signature = random.randint(0, 1)
        sabotage_data = random.randint(0, 1)
        dont_request_certificate = random.randint(0, 1)
        revoke_certificate = random.randint(0, 1)

        if not dont_request_certificate:
            # Entity requests a certificate from the CA
            if time_expired:
                entity.request_certificate(ca=ca, hours_limit=0)
            else:
                entity.request_certificate(ca=ca)

        # Entity signs some data
        data = generate_random_string(random.randint(1, 100))

        # We ask the entity to sign data despite noe having a certificate from CA
        if dont_request_certificate:
            try:
                entity.sign_data(data)
            except Exception as e:
                if not re.search(r'Entity does not have a valid certificate.*', str(e)):
                    error = 1
                    print("\nVerification for test " + str(i) + " failed: Non-certified Entity signed data")
                    break
            else:
                error = 1
                print("\nVerification for test " + str(i) + " failed: Non-certified Entity signed data")
                break

            continue

        if not sabotage_signature:
            signature = entity.sign_data(data=data)
        else:
            signature = "XOXO"

        # Relying Party verifies the signed data
        is_verified = relying_party.verify_signed_data(entity=entity, ca=ca, data=data, signature=signature)

        if not is_verified and not time_expired and not sabotage_signature:
            error = 1
            print("\nVerification for test " + str(i) + " failed")
            break
        if is_verified and (time_expired or sabotage_signature):
            error = 1
            print("\nVerification for test " + str(i) + " failed, " + "time_expired = " + str(
                time_expired) + ", sabotage_signature =" + str(sabotage_signature))
            break

        # Encrypt and decrypt data
        recipient = Entity()
        recipient.request_certificate(ca=ca)

        if not sabotage_data:
            encrypted_data = entity.encrypt_data(data=data, recipient_public_key=relying_party.public_key)
        else:
            encrypted_data = entity.encrypt_data(data="XXXX", recipient_public_key=relying_party.public_key)

        signature = recipient.sign_data(data=encrypted_data)

        # Relying Party verifies the signed data
        is_verified = relying_party.verify_signed_data(entity=recipient, ca=ca, data=encrypted_data,
                                                       signature=signature)
        decrypted_data = relying_party.decrypt_data(encrypted_data=encrypted_data)

        if not is_verified:
            error = 1
            print("\nVerification for test " + str(i) + " failed")
            break

        if not sabotage_data:
            if decrypted_data != data:
                error = 1
                print("\nDecryption for test " + str(i) + " failed")
                break
        if sabotage_data:
            if decrypted_data == data:
                error = 1
                print("\nDecryption for test " + str(i) + " failed, after sabotaging data")
                break

        become_ca = entity.request_cs_authority(ca=ca)

        if become_ca:
            entity2 = Entity()

            relying_party = RelyingParty()
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
            is_verified = relying_party.verify_signed_data(entity=entity2, ca=entity, data=data, signature=signature)

            if not is_verified and not time_expired and not sabotage_signature:
                error = 1
                print("\nVerification for test " + str(i) + " failed")
                break
            if is_verified and (time_expired or sabotage_signature):
                error = 1
                print("\nVerification for test " + str(i) + " failed, " + "time_expired = " + str(
                    time_expired) + ", sabotage_signature =" + str(sabotage_signature))
                break

            # New Entity trying to request CA Authorities from 2nd Entity,
            # Which is not a CA
            entity3 = Entity()
            entity4 = Entity()
            relying_party = RelyingParty()

            entity3.request_cs_authority(ca=entity2)
            entity4.request_certificate(ca=entity3)

            if not (entity4.certificate == False):
                error = 1
                print("\nEntity acted as CA without permission for test " + str(i))
                break

        else:
            entity2 = Entity()

            # New Entity trying to request certificate from old Entity,
            # Which is not a CA
            relying_party = RelyingParty()
            entity2.request_certificate(ca=entity)

            if not (entity2.certificate == False):
                error = 1
                print("\nEntity acted as CA without permission for test " + str(i))
                break

        if revoke_certificate:
            relying_party.request_certificate_revokation(ca=ca, entity_name=entity.name, signature=entity.certificate)
            is_verified = relying_party.verify_signed_data(entity=entity, ca=ca, data=encrypted_data,
                                                           signature=signature)

            if is_verified:
                error = 1
                print("\nVerification for test " + str(i) + " failed")
                print("\nData was verified despite certificate was revoked")
                break

        # Testing mulitple entities and CAs on a single relying party

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

        # Trying to use a different CA for the same entity
        entity1.request_certificate(ca=ca2)
        signature4 = entity1.sign_data(data1)
        is_verified4 = relying_party.verify_signed_data(entity=entity1, ca=ca2, data=data1, signature=signature4)

        if not is_verified1:
            error = 1
            print("\nVerification for test " + str(i) + " failed")
            print("\nFailed to verify first entity inside the Relying Party")
            break
        if not is_verified2:
            error = 1
            print("\nVerification for test " + str(i) + " failed")
            print("\nFailed to verify second entity inside the Relying Party")
            break
        if not is_verified3:
            error = 1
            print("\nVerification for test " + str(i) + " failed")
            print("\nFailed to verify third entity (from different CA) inside the Relying Party")
            break
        if not is_verified4:
            error = 1
            print("\nVerification for test " + str(i) + " failed")
            print("\nFailed to verify first entity with different CA inside the Relying Party")
            break

    if error == 0:
        print("\nAll " + str(num_of_tests) + " tests PASSED")
    else:
        print("\nSome test FAILED")
