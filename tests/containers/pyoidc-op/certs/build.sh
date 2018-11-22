set -ex

# Use all the certificate files created in the first run.
cd generate-certs
bash generate.sh
mv output/* ..

# Do another run (create another, independent, certificate
# hierarchy) and then use that unrelated ca-chain.pem
# for tests.
rm -rf output
bash generate.sh
mv output/ca-chain.pem ../ca-chain-no-match.pem

