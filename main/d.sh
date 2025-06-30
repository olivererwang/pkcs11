# This script sets up a Docker container with SoftHSM and PKCS#11 tools for cryptographic operations.
docker run -d -v ./:/app pkcs11-base tail -f /dev/null


## /opt/homebrew/var/lib/softhsm/tokens 存储位置
## so位置 /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so

# This script demonstrates how to use SoftHSM with pkcs11-tool to manage cryptographic keys.

# show SoftHSM slots
softhsm2-util --show-slots

# sets up a SoftHSM token with a label and PIN
softhsm2-util --init-token --slot 0 --label 1234 --pin 1234 --so-pin 1234

softhsm2-util --delete-token --label 1234 --pin 1234 --so-pin 1234


# lists objects in a SoftHSM token using pkcs11-tool.
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so  --slot 0x7f17d9a6 --login --pin 1234 --list-objects

# create a new key pair in the SoftHSM token
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so  --slot 0x7f17d9a6 --login --pin 1234 --keypairgen --label pk-rsa-key --key-type rsa:2048

# decrypt message using the private key
# 先把hex转成二进制文件
xxd -r -p msg.hex msg.bin
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so  --slot 0x7f17d9a6 --login --pin 1234 --decrypt --label pk-rsa-key --mechanism RSA-PKCS -i test_data/msg.bin -o test_data/msg.txt

# generates a self-signed certificate using the new key pair
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so  --slot 0x7f17d9a6  --label pk-rsa-key --login --pin 1234 --sign --type cert --output-file cert.pem

# exports the public key from the SoftHSM token
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so  --slot 0x7f17d9a6  --label pk-rsa-key --login --pin 1234 --read-object --type pubkey --output-file pubkey.der
# convert the public key from DER to PEM format
openssl rsa -pubin -inform DER -in pubkey.der -outform PEM -out pubkey.pem


# generate a new key pair via openssl
openssl genrsa -out openssl-rsa-key.pem 2048
# convert the openssl private key to pkcs8 format
openssl pkcs8 -topk8 -inform PEM -outform DER -in openssl-rsa-key.pem -out openssl-rsa-key.pk8 -nocrypt
# import the openssl private key into SoftHSM
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so  --slot 0x7f17d9a6 --login --pin 1234 --write-object openssl-rsa-key.pk8 --type privkey --label openssl-rsa-key
# convert the openssl private key to public key with pem format
openssl rsa -in openssl-rsa-key.pem -pubout -outform PEM -out openssl-rsa-key.pub
# import the openssl public key into SoftHSM
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so  --slot 0x7f17d9a6 --login --pin 1234 --write-object openssl-rsa-key.pub --type pubkey --label openssl-rsa-pubkey