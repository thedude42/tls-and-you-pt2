#!/bin/bash

CERTS_DIR="$(pwd)/certs"
ROOT_CA_KEY="$CERTS_DIR/rootca.key"
ROOT_CA="$CERTS_DIR/rootca.pem"
ROOT_CONFIG="$CERTS_DIR/root_ca.conf"
INTERMEDIATE_CONFIG="$CERTS_DIR/intermediate_ca.conf"
INTERMEDIATE_KEY="$CERTS_DIR/intermediateca.key"
INTERMEDIATE_CSR="$CERTS_DIR/intermediate.csr"
INTERMEDIATE="$CERTS_DIR/intermediate.pem"
INTERMEDIATE_SERIALS="$CERTS_DIR/serial.txt"
INTERMEDIATE_DB="$CERTS_DIR/index.txt"
END_CERT_ID="example.com"
END_CERT_CONFIG="$CERTS_DIR/$END_CERT_ID.conf"
END_CERT_KEY="$CERTS_DIR/$END_CERT_ID.key"
END_CERT_CSR="$CERTS_DIR/$END_CERT_ID.csr"
END_CERT="$CERTS_DIR/$END_CERT_ID.pem"

rm -rf $CERTS_DIR && mkdir $CERTS_DIR
touch $CERTS_DIR/rootindex.txt
touch $CERTS_DIR/rootindex.txt.attr
echo "00" >$CERTS_DIR/rootserial
echo "00" >$INTERMEDIATE_SERIALS
touch $INTERMEDIATE_DB
touch $INTERMEDIATE_DB.attr

# Root CA CSR config
cat <<EOF >$ROOT_CONFIG
[ ca ]
default_ca = CA_default

[ CA_default ]
certificate       = $ROOT_CA
private_key       = $ROOT_CA_KEY
new_certs_dir     = $CERTS_DIR
database          = $CERTS_DIR/rootindex.txt
serial            = $CERTS_DIR/rootserial
default_days      = 750
policy            = policy_strict

[ policy_strict ]
countryName             = match
stateOrProvinceName     = match
organizationName        = match
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ policy_loose ]
countryName             = optional
stateOrProvinceName     = optional
localityName            = optional
organizationName        = optional
organizationalUnitName  = optional
commonName              = supplied
emailAddress            = optional

[ req ]
default_bits            = 2048
default_md              = sha256
prompt                  = no
utf8                    = yes
distinguished_name      = EXAMPLE_ROOT_CA
string_mask             = utf8only
x509_extensions         = v3

[ EXAMPLE_ROOT_CA ]
countryName             = US
stateOrProvinceName     = WA
localityName            = Seattle
0.organizationName      = Johnny's Demo
commonName              = ROOT CA
emailAddress            = johnny.schmidt@smartsheet.com

[ v3 ]
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid:always,issuer
basicConstraints        = critical, CA:true
keyUsage                = critical, digitalSignature, cRLSign, keyCertSign
EOF

# Intermediate CA CSR config
cat <<EOF >$INTERMEDIATE_CONFIG
[ ca ]
default_ca    = CA_default      # The default ca section

[ CA_default ]
certificate      = $INTERMEDIATE
private_key      = $INTERMEDIATE_KEY
database         = $INTERMEDIATE_DB    # Database index file
serial           = $INTERMEDIATE_SERIALS
new_certs_dir    = $CERTS_DIR
default_days     = 365         # How long to certify for
default_crl_days = 30           # How long before next CRL
default_md       = sha256       # Use public key default MD
preserve         = no           # Keep passed DN ordering

[ req ]
default_bits            = 4096
default_md              = sha256
prompt                  = no
utf8                    = yes
distinguished_name      = EXAMPLE_INTERMEDIATE_CA
string_mask             = utf8only
x509_extensions         = v3

[ EXAMPLE_INTERMEDIATE_CA ]
countryName             = US
stateOrProvinceName     = WA
localityName            = Seattle
0.organizationName      = Johnny's Demo
commonName              = INTERMEDIATE CA
emailAddress            = johnny.schmidt@smartsheet.com

[ v3 ]
basicConstraints        = critical, CA:true, pathlen:0
keyUsage                = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier    = hash
authorityKeyIdentifier  = keyid

[bc_section]
CA=true
pathlen=2

[ signing_policy ]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[ signing_req ]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
basicConstraints       = CA:FALSE
keyUsage               = digitalSignature, keyEncipherment
EOF

# Client cert CSR config
cat <<EOF >$END_CERT_CONFIG
[ req ]
default_bits            = 2048
prompt                  = no
utf8                    = yes
distinguished_name      = CERT1
string_mask             = utf8only
req_extensions          = v3

[ CERT1 ]
countryName             = US
stateOrProvinceName     = WA
localityName            = Seattle
organizationName        = Johnny's Demo
commonName              = server.example.com
emailAddress            = johnny.schmidt@smartsheet.com

[ v3 ]
basicConstraints        = CA:FALSE
keyUsage                = digitalSignature, keyEncipherment
subjectKeyIdentifier    = hash
extendedKeyUsage        = clientAuth,serverAuth

EOF

function make_root_ca() {
  echo "generating private key for root CA"
  openssl genrsa -out $ROOT_CA_KEY 2048
  echo "self-signing the root ca using the root config"
  openssl req -new -x509 \
    -key $ROOT_CA_KEY \
    -config $ROOT_CONFIG \
    -out $ROOT_CA
}

function make_intermediate_ca() {
  echo "generating private key for intermediate CA"
  openssl genrsa \
    -out $INTERMEDIATE_KEY 4096
  echo "creating the signing request for the intermediate CA"
  openssl req \
    -new \
    -key $INTERMEDIATE_KEY \
    -out $INTERMEDIATE_CSR \
    -config $INTERMEDIATE_CONFIG
  echo "signing intermediate CA with root CA using intermediate ca config"
  openssl ca \
    -batch \
    -config $ROOT_CONFIG \
    -extensions v3 \
    -days 3650 \
    -notext \
    -md sha256 \
    -in $INTERMEDIATE_CSR \
    -out $INTERMEDIATE

  validate_cert $INTERMEDIATE $ROOT_CA \
    "Checking ROOT signed INTERMEDIATE"
}

function make_end_cert() {
  # echo "generating key for $EXAMPLE"
  # openssl genrsa -out $EXAMPLE.key 2048
  # echo "establishing public key file for $EXAMPLE"
  # openssl rsa -in $EXAMPLE.key -pubout -out $EXAMPLE.pub
  echo "generating CSR for $EXAMPLE"
  # openssl req -new -key $EXAMPLE.key -out $EXAMPLE.csr
  openssl req \
    -config $END_CERT_CONFIG \
    -newkey rsa:2048 \
    -keyout $END_CERT_KEY \
    -sha256 \
    -nodes \
    -out $END_CERT_CSR \
    -outform PEM
  echo "signing the end-host certificate"
  openssl ca \
    -batch \
    -config $INTERMEDIATE_CONFIG \
    -policy signing_policy \
    -extensions signing_req \
    -keyfile $INTERMEDIATE_KEY \
    -out $END_CERT \
    -infiles $END_CERT_CSR
  validate_cert $END_CERT <(cat $INTERMEDIATE $ROOT_CA) \
    "Checking $INTERMEDIATE signd $END_CERT"
}

function validate_cert() {
  local cert="$1"
  local chain="$2"
  local msg="$3"
  if [ -z $cert ] || [ -z $chain ]; then
    echo "validate_cert(): missing argument"
    echo "cert=$cert | chain=$chain"
    exit 1
  fi
  if [ -z "$msg" ]; then
    msg="verify cert(s) at $chain signed the chain for cert at $cert:"
  fi
  echo "$msg"
  RESULT=$(openssl verify -trusted $chain $cert 2>&1)
  if grep -q OK <<<$RESULT; then
    echo -e "\033[0;32m$RESULT"
  else
    echo -e "\033[0;31m$RESULT"
    exit 1
  fi
  echo -e "\033[0;0m"
}

make_root_ca
make_intermediate_ca
make_end_cert
