## /opt/homebrew/var/lib/softhsm/tokens 存储位置
## so位置 /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so

# This script demonstrates how to use SoftHSM with pkcs11-tool to manage cryptographic keys.

# show SoftHSM slots
softhsm2-util --show-slots

# sets up a SoftHSM token with a label and PIN
softhsm2-util --init-token --slot 0 --label 1234 --pin 1234 --so-pin 1234
softhsm2-util --init-token --slot 0 --label 5678 --pin 5678 --so-pin 5678


# lists objects in a SoftHSM token using pkcs11-tool.



# create a new key pair in the SoftHSM token
pkcs11-tool --module /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so --slot 0x9d57a4f  --label 1234 --login --pin 1234 --keypairgen --key-type rsa:2048

# generates a self-signed certificate using the new key pair
pkcs11-tool --module /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so --slot 0x9d57a4f  --label 1234 --login --pin 1234 --sign --type cert --output-file cert.pem

# lists objects again to see the self-signed certificate
pkcs11-tool --module /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so  --slot 0x9d57a4f  --label 1234  --login --pin 1234 --list-objects

# exports the public key from the SoftHSM token
pkcs11-tool --module /opt/homebrew/Cellar/softhsm/2.6.1/lib/softhsm/libsofthsm2.so --slot 0x9d57a4f  --label 1234 --login --pin 1234 --read-object --type pubkey --output-file pubkey.der
# convert the public key from DER to PEM format
openssl rsa -pubin -inform DER -in pubkey.der -outform PEM -out pubkey.pem

