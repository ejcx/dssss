# Dead Simple Secret Store Service - dssss
dssss is a simple secret store for AWS. dssss is secure, easy to setup, launch, and requires no fine-tuning.

dssss is specifically for AWS. It provides an API that will:
 - Read, write, and scope secrets to specific IAM roles.
 - Authenticate users based on IAM Role.
 
The intersection of security and usability is the most important thing to dssss. 

## Getting started with dssss
dssss does not require any configuration, bootstrapping setup process, or role/policy configuration.

What dssss does require is access to KMS and the AWS Parameter store. When dssss is run for the first time it will do the following things:

  - Create a new KMS Master Key.
  - Generate a new KMS Data Key associated with that KMS master key.
  - Generate a "seal" key.
  - Store a dssss configuration in the AWS parameter store.

After the first time dssss is run, dssss will just pull its configuration
out of the AWS parameter store and start the server.

Running dssss is as easy as:
```
$ dssss
```

For more information about what each component is used for, especially what
they encryption keys are used for, consult the cryptography details section.

## API 
dssss is meant to have a very small and easy to grok API.

### Authentication
There are two methods to authenticate with dssss.

##### PKCS7 Authentication
The first method is using a signed PKCS7 object given to your EC2 Instance from the [AWS Metadata service.](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html).

When authenticating with dssss, use the `Authentication` header to authenticate with dssss.

```
$ curl http://dssss.local -H "Authentication: $(curl -s http://169.254.169.254/latest/dynamic/instance-identity/pkcs7 | tr -d '\n')'"
```
##### Reauthentication
If you are making multiple requests to dssss, pkcs7 auth can be slow since it requires the use of AWS APIs.

Because of this latency, once you authenticate with the PKCS7 `Authentication` header, dssss will also return a `ReAuthentication` token that can be used for 15 minutes.

Here is an example:
```
$ curl http://dssss.local/v1/auth -H "Authentication: $(cat auth/dd)" -v
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8000 (#0)
> GET /v1/auth HTTP/1.1
> Host: 127.0.0.1:8000
> User-Agent: curl/7.51.0
> Accept: */*
> Authentication: MIAGCSqGSIb3DQEHAqCAMIACAQExCzAJBgUrDgMCGgUAMIAGCSqGSIb3DQEHAaCAJIAEggGwewogICJkZXZwYXlQcm9kdWN0Q29kZXMiIDogbnVsbCwKICAicHJpdmF0ZUlwIiA6ICIx
NzIuMzEuMTUuMjI1IiwKICAiYXZhaWxhYmlsaXR5Wm9uZSIgOiAidXMtd2VzdC0xYSIsCiAgInZlcnNpb24iIDogIjIwMTAtMDgtMzEiLAogICJpbnN0YW5jZUlkIiA6ICJpLTAwMjZjM2FmM2IzYzRlODFlIi
wKICAiYmlsbGluZ1Byb2R1Y3RzIiA6IG51bGwsCiAgImluc3RhbmNlVHlwZSIgOiAidDIuc21hbGwiLAogICJpbWFnZUlkIiA6ICJhbWktMmFmYmRlNGEiLAogICJwZW5kaW5nVGltZSIgOiAiMjAxNy0wNS0z
MVQwMzo0Njo1N1oiLAogICJhY2NvdW50SWQiIDogIjM1NDMyMjQ1ODQ4MyIsCiAgImFyY2hpdGVjdHVyZSIgOiAieDg2XzY0IiwKICAia2VybmVsSWQiIDogbnVsbCwKICAicmFtZGlza0lkIiA6IG51bGwsCi
AgInJlZ2lvbiIgOiAidXMtd2VzdC0xIgp9AAAAAAAAMYIBFzCCARMCAQEwaTBcMQswCQYDVQQGEwJVUzEZMBcGA1UECBMQV2FzaGluZ3RvbiBTdGF0ZTEQMA4GA1UEBxMHU2VhdHRsZTEgMB4GA1UEChMXQW1h
em9uIFdlYiBTZXJ2aWNlcyBMTEMCCQCWukjZ5V4aZzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcNAQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTcwNTMxMDM0NzAxWjAjBgkqhkiG9w0BCQQxFgQUNILTt3nygCCCH+uv2gKrTxKSJ3kwCQYHKoZIzjgEAwQuMCwCFFrCKyqoYKiepd9zvomHfpgMJgnQAhQqjLHWuCPMojwOWyapFf9Zcb8GjwAAAAAAAA==
>
< HTTP/1.1 200 OK
< Reauthentication: d15d2123fe7fd555e58c5ed554293cdeb8d6c1a4617790f8bd32bbc19ca4fcb935e33e35dc5d438d4c7610f87f12874440e31c617c23cf9e7ee0cc3faa0328bbf0cbabc6563a2673b97db4cf0a72d9525dde208cc517c907ffc5c360c789f0fd3452ea857ee4e83a1b83afca5e218c7f4a4495a80fb8e291f6af65e9f871a92b09afa8f756b8969c85765b4eaf954839699b61c3
2090bc803237c94d857cf693c6943248ae43eaa0ab0ee0701a4ba2128b7c8929c205152914401a26b3f25432c99c755a8c
< Date: Mon, 12 Jun 2017 01:52:48 GMT
< Content-Length: 0
< Content-Type: text/plain; charset=utf-8
<
* Curl_http_done: called premature == 0
* Connection #0 to host 127.0.0.1 left intact
```

Now, the `Reauthentication` header can be used to authentication for the next 15 minutes.

```
e :) curl http://127.0.0.1:8000/v1/auth -H "Reauthentication: d15d2123fe7fd555e58c5ed554293cdeb8d6c1a4617790f8bd32bbc19ca4fcb935e33e35dc5d438d4c7610f87f12874440e31c617c23cf9e7ee0cc3faa0328bbf0cbabc6563a2673b97db4cf0a72d9525dde208cc517c907ffc5c360c789f0fd3452ea857ee4e83a1b83afca5e218c7f4a4495a80fb8e291f6af65e9f871a9
2b09afa8f756b8969c85765b4eaf954839699b61c32090bc803237c94d857cf693c6943248ae43eaa0ab0ee0701a4ba2128b7c8929c205152914401a26b3f25432c99c755a8c" -v
*   Trying 127.0.0.1...
* TCP_NODELAY set
* Connected to 127.0.0.1 (127.0.0.1) port 8000 (#0)
> GET /v1/auth HTTP/1.1
> Host: 127.0.0.1:8000
> User-Agent: curl/7.51.0
> Accept: */*
> Reauthentication: d15d2123fe7fd555e58c5ed554293cdeb8d6c1a4617790f8bd32bbc19ca4fcb935e33e35dc5d438d4c7610f87f12874440e31c617c23cf9e7ee0cc3faa0328bbf0cbabc6563a2673b97db4cf0a72d9525dde208cc517c907ffc5c360c789f0fd3452ea857ee4e83a1b83afca5e218c7f4a4495a80fb8e291f6af65e9f871a92b09afa8f756b8969c85765b4eaf954839699b61c3
2090bc803237c94d857cf693c6943248ae43eaa0ab0ee0701a4ba2128b7c8929c205152914401a26b3f25432c99c755a8c
```
## Administration
### Distinguished roles
dssss introduces the concept of *distinguished roles*.

Within dssss, administration is required to be done from IAM Roles
with a specific names. These roles are:
```
  dssssadmin
```

It is easy to specify additional distinguished roles however. This can be done by providing additional parameters to dssss when it is starting.

This command will tell dssss that `myadminrole` and `testrole` are also distinguished roles that can administer the dssss secret store.
```
$ dssss myadminrole testrole
```

## Cryptography
It's important to outline the cryptographic details of how dssss encrypts, stores, and accesses secrets.
### Algorithms
dssss uses only symmetric key AEADs to encrypt and decrypt secrets in the secret store.. The underlying
cryptographic primitives are provided through the crypto/secretbox golang package. crypto/secretbox uses XSalsa20 and Poly1305 to encrypt and authenticate all ciphertexts.

When using the secretbox AEAD interface, it's important to avoid
nonce reuse. A new 24 byte random nonce is generated from `urandom`
each time `Seal` is called.

### Init Process
When `dssss` is run for the first time, there are several things that happen behind the scenes.

First a KMS master secret key is created. From this key, a secret data key is generated. 

A master seal key is also generated by dssss. This master seal key is encrypted by the AWS KMS Data key, and is used to encrypt individual secret entries.

### Secret Storage
Each secret is encrypted with a unique, per secret, key. This per-secret key is stored encrypted by the master seal key. Along with the secret, the roles necessary to access the secret are also encrypted
alongside the secret.

The integrity of the roles is what is important to maintain, and this is provided with authenticated encryption.

### Nonces
It's important to note that each nonce is 24 bytes and randomly generated. You can see this in the `Seal` function within the `dssss/dc` package.

### Reauthentication
Reauthentication tokens are simply encrypted JSON objects. The object is encrypted with secretbox, and a randomly generated Reauthentication header key is created when dssss starts.

