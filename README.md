# Dead Simple Secret Store Service - dssss
dssss is a simple secret store for services that is secure, easy to
configure and launch, requires absolutely no fine-tuning.

dssss is specifically for AWS. It provides an API that will:
 - Read, write, and scope secrets to specific IAM roles.
 - Authenticate users based on IAM Role.


## Getting started with dssss
dssss requires master secret. Running the generate sub-command
will get you started by generating a master secret and a master
token for administrative tasks.

```
$ ./dsss init
MasterKey: 00000000000000000000000000000000
```

## Administration
### Distinguished roles
dssss introduces the concept of *distinguished roles*.

Within dssss, administration is required to be done from the 
## Cryptography It's important to outline the cryptographic details of how dssss encrypts, stores, and accesses secrets.
### Algorithms
All cryptographic algorithms symmetric key AEADs. The underlying
cryptographic primitives are provided through the crypto/secretbox
golang package. crypto/secretbox uses XSalsa20 and Poly1305 to
encrypt and authenticate all ciphertexts.

When using the secretbox AEAD interface, it's important to avoid
nonce reuse. A new 24 byte random nonce is generated from `urandom`
each time `Seal` is called.

### Init Process
When `./dssss init` is run, dssss will generate two secret keys.

The first secret key is the master key. This is the key that
is used to decrypt individual secret entries. The second secret
key that is generated is the seal key. The seal key is the key
that encrypts the master key.

### Secret Storage
Each secret is encrypted with a unique, per secret, key. Along with
the secret, the roles necessary to access the secret are also encrypted
alongside the secret.

The integrity of the roles is what is important to maintain, and this
is provided with authenticated encryption.

