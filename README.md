# Dead Simple Secret Store Service - dssss
dssss is a simple secret store for services that is secure, easy to
configure and launch, requires absolutely no fine-tuning.

dssss is specifically for AWS. It provides an API that will:
 - Read, write, and scope secrets to specific IAM roles.
 - Authenticate users based on IAM Role.


## Getting started with dssss
dssss does not require any configuration or bootstrapping setup process.

What dssss does require is access to KMS and the AWS Parameter store. When
dssss is run for the first time it will do the following things.

  - Create a new KMS Master Key.
  - Generate a new data key associated with that master key.
  - Generate a "seal" key. 
  - Store a dssss configuration in the AWS parameter store.

After the first time dssss is run, dssss will just pull its configuration
out of the AWS parameter store and start the server.

Running dssss is as easy as:
```
$ ./dssss
```

For more information about what each component is used for, especially what
they encryption keys are used for, consult the cryptography details section.

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

