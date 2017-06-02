# webMethods Integration Server package for PGP
This project provides a sample Integration Server package for PGP encryption and decryption. It is using the Bouncy Castle library (https://www.bouncycastle.org/, version 145).

## Requirements

The project was developed and tested on the following installation:
1. Integration Server 9.12
2. Software AG Designer 9.12 with Service Development

## Quick start

To install the project on your local development environment follow these steps.
1. Checkout the repository to your development environment
2. Copy the ```PGP``` folder to ```<install_dir>/IntegrationServer/instances/<instance>/packages```.
3. Download the following Bouncy Castle libraries and copy to ```<install_dir>/IntegrationServer/instances/<instance>/packages/PGP/code/jars/static```
    1. http://www.bouncycastle.org/archive/145/bcprov-jdk15-145.jar
    2. http://www.bouncycastle.org/archive/145/bcpg-jdk15-145.jar
3. Restart Integration Server

## Run tests

There are tests provided in ```pgp.test```

### Decrypt

- **decrypt:testDecryptAndVerifyFile:** Decrypt file and verify its signature
- **decrypt:testDecryptAndVerifyString:** Decrypt signed string and verify its signature
- **decrypt:testDecryptAndVerifyUnsignedString:** Decrypt unsigned string and verify its signature
- **decrypt:testDecryptFile:** Decrypt file (no signature verification)
- **decrypt:testDecryptString:** Decrypt string (no signature verification)

### Encrypt
- **encrypt:testEncryptAndSignFile:** Encrypt and sign file
- **encrypt:testEncryptAndSignString:** Encrypt and sign string
- **encrypt:testEncryptFile:** Encrypt file (no signing)
- **encrypt:testEncryptString:** Encrypt string (no signing)

### Keys
- **keys:testListAlgorithms:** List all supported algorithms
- **keys:testReadPrivateKeys:** Read a private key by user id
- **keys:testReadPublicKeys:** Read a public key by user id


## Key-Configuration

Configuration of RSA keys is done in ```\config\config.xml```. A demo configuration is provided with this package.
```Note: package assumes keys to be located in \pub\keys. In the configuration provide filenames only (without path).```

## Provided RSA keys

The package comes with two RSA keys for users ```alice``` and ```bob```. You can find the RSA keys in ```\pub\keys```. The keys have been generated using https://www.igolder.com/pgp/generate-key/
- **alice-pub.asc:** Alice's public key
- **alice-sec.asc:** Alice's private key, secret: ```alice```
- **bob-pub.asc:** Bob's public key
- **bob-sec.asc:** Bob's private key, secret: ```bob```

## Supported Algorithms

###Key Exchange Algorithms
- ELGAMAL_ENCRYPT
- DSA
- RSA
- EC
- RSA_ENCRYP
- ECDSA
- RSA_SIGN
- ELGAMAL
- DH

### Encryption Algorithms
- IDEA
- TRIPLE_DES
- CAST5
- BLOWFISH
- SAFER
- DES
- AES_128
- AES_192
- AES_256
- TWOFISH

### Signature Algorithms
- MD5
- SHA1
- RIPEMD160
- DOUBLE_SHA
- MD2
- TIGER 192
- HAVAL_5_160
- SHA256
- SHA384
- SHA512
- SHA224

______________________
These tools are provided as-is and without warranty or support. They do not constitute part of the Software AG product suite. Users are free to use, fork and modify them, subject to the license agreement. While Software AG welcomes contributions, we cannot guarantee to include every contribution in the master project.
_____________
Contact us at [TECHcommunity](mailto:technologycommunity@softwareag.com?subject=Github/SoftwareAG) if you have any questions.
