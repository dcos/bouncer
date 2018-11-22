#!/bin/bash
# Copyright (C) Mesosphere, Inc. See LICENSE file for details.
# Author: Jan-Philip Gehrcke

# Resources:
#
# https://www.openssl.org/docs/manmaster/man1/req.html
# (especially -batch and prompt)
# http://stackoverflow.com/a/9669699/145400
# https://bitbucket.org/stefanholek/pki-example-1/src
# http://pki-tutorial.readthedocs.io/en/latest/simple/index.html

set -ex

# Clean up from previous run.
rm -rf output ca certs

# Create Root CA.
mkdir -p ca/root-ca/private ca/root-ca/db certs
chmod 700 ca/root-ca/private
cp /dev/null ca/root-ca/db/root-ca.db
cp /dev/null ca/root-ca/db/root-ca.db.attr
echo 01 > ca/root-ca/db/root-ca.crt.srl
echo 01 > ca/root-ca/db/root-ca.crl.srl

openssl req -new \
    -batch \
    -config root-ca.conf \
    -out ca/root-ca.csr \
    -keyout ca/root-ca/private/root-ca.key

openssl ca -selfsign \
    -batch \
    -config root-ca.conf \
    -in ca/root-ca.csr \
    -out ca/root-ca.crt \
    -extensions root_ca_ext


# Create Signing CA.
mkdir -p ca/signing-ca/private ca/signing-ca/db certs
chmod 700 ca/signing-ca/private
cp /dev/null ca/signing-ca/db/signing-ca.db
cp /dev/null ca/signing-ca/db/signing-ca.db.attr
echo 01 > ca/signing-ca/db/signing-ca.crt.srl
echo 01 > ca/signing-ca/db/signing-ca.crl.srl

openssl req -new \
    -batch \
    -config signing-ca.conf \
    -out ca/signing-ca.csr \
    -keyout ca/signing-ca/private/signing-ca.key

openssl ca \
    -batch \
    -config root-ca.conf \
    -in ca/signing-ca.csr \
    -out ca/signing-ca.crt \
    -extensions signing_ca_ext

# Create server certificates signing request(s) and cert(s).
for certname in oidc-idp-SAN-DNS-bouncer-test-hostmachine oidc-idp-SAN-DNS-los-pollos; do
    openssl req -new \
        -batch \
        -config ${certname}.conf \
        -out certs/${certname}.csr \
        -keyout certs/${certname}.key

    openssl ca \
        -batch \
        -config signing-ca.conf \
        -in certs/${certname}.csr \
        -out certs/${certname}.crt \
        -extensions client_server_cert_ext
done

# Create file with root CA certificate and intermediate CA certificate.
cat ca/signing-ca.crt ca/root-ca.crt > ca/ca-chain.pem

# Create output directory.
mkdir -p output

pushd certs
cp *.crt ../output
cp *.key ../output
popd
cp ca/ca-chain.pem output
