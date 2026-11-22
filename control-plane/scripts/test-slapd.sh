#!/usr/bin/env bash
# Start a throwaway OpenLDAP server (LDAPS, self-signed CA) for the AD-driver integration tests.
# Usage: scripts/test-slapd.sh <workdir> [port]   -> prints export lines for the test run.
set -euo pipefail
D=${1:?workdir}; PORT=${2:-56636}
rm -rf "$D"; mkdir -p "$D/db"
cd "$D"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=oplia-test-ca" -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\n" > san.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 -extfile san.ext -out server.crt 2>/dev/null
chmod 0644 server.key
PW=$(openssl rand -hex 16)
HASH=$(slappasswd -s "$PW")
cat > slapd.conf <<CONF
include /etc/ldap/schema/core.schema
include /etc/ldap/schema/cosine.schema
include /etc/ldap/schema/inetorgperson.schema
pidfile $D/slapd.pid
modulepath /usr/lib/ldap
moduleload back_mdb
TLSCACertificateFile $D/ca.crt
TLSCertificateFile $D/server.crt
TLSCertificateKeyFile $D/server.key
database mdb
suffix "dc=oplia,dc=test"
rootdn "cn=admin,dc=oplia,dc=test"
rootpw $HASH
directory $D/db
CONF
slapd -f slapd.conf -h "ldaps://127.0.0.1:$PORT/"
for _ in $(seq 1 50); do [ -s slapd.pid ] && break; sleep 0.1; done
export LDAPTLS_CACERT="$D/ca.crt"
ldapadd -x -H "ldaps://127.0.0.1:$PORT" -D "cn=admin,dc=oplia,dc=test" -w "$PW" >/dev/null <<LDIF
dn: dc=oplia,dc=test
objectClass: dcObject
objectClass: organization
o: oplia
dc: oplia

dn: ou=people,dc=oplia,dc=test
objectClass: organizationalUnit
ou: people

dn: ou=groups,dc=oplia,dc=test
objectClass: organizationalUnit
ou: groups

dn: uid=alice,ou=people,dc=oplia,dc=test
objectClass: inetOrgPerson
uid: alice
cn: Alice
sn: A

dn: uid=bob,ou=people,dc=oplia,dc=test
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: B

dn: cn=platform-admins,ou=groups,dc=oplia,dc=test
objectClass: groupOfNames
cn: platform-admins
member: uid=bob,ou=people,dc=oplia,dc=test
LDIF
echo "export OPLIA_TEST_LDAP_URL=ldaps://127.0.0.1:$PORT"
echo "export OPLIA_TEST_LDAP_CA=$D/ca.crt"
echo "export OPLIA_TEST_LDAP_PW=$PW"
