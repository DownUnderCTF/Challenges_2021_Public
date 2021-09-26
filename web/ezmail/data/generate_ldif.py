import faker
import uuid
import secrets

NUM_USERS = 64
GENERATE_ROOT = True
FLAG = open('../flag.txt', 'r').read().strip()

fake = faker.Faker()

block = lambda b: "\n".join(b) + '\n\n'

with open('users.ldif', 'w') as f:
    if GENERATE_ROOT:
        f.write(block([
            "dn: dc=ductf,dc=org",
            "objectClass: dcObject",
            "objectClass: organization",
            "dc: ductf",
            "o: ductf"
        ]))
        f.write(block([
            "dn: ou=users,dc=ductf,dc=org",
            "objectClass: organizationalUnit",
            "ou: users",
        ]))

    cns = []

    f.write(block([
        "dn: cn=admin,ou=users,dc=ductf,dc=org",
        "cn: admin",
        "sn: admin",
        "objectClass: inetOrgPerson",
        "uid: "+str(uuid.uuid4()),
        "userPassword: "+FLAG
    ]))

    for i in range(NUM_USERS):
        cn = fake.user_name()
        cns.append(cn)

        f.write(block([
            "dn: cn="+cn+",ou=users,dc=ductf,dc=org",
            "cn: "+cn,
            "sn: "+cn.title(),
            "objectClass: inetOrgPerson",
            "uid: "+str(uuid.uuid4()),
            "userPassword: "+secrets.token_hex(24),
        ]))

    f.write(block([
        "dn: cn=ezmail,ou=users,dc=ductf,dc=org",
        "cn: ezmail",
        "objectClass: groupOfNames"
    ] + [
        f"member: cn={cn},ou=users,dc=ductf,dc=org" for cn in cns
    ]))
