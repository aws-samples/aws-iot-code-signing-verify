# Self-sign

To digitally sign firmware images, you need a code-signing certificate and a private key.  For testing purposes, you can create a self‐signed certificate and private key.  For production environments, purchase a certificate through a well‐known certificate authority (CA).

We recommend that you purchase a code signing certificate from a company with a good reputation for security. Do not use a self-signed certificate for any purpose other than testing.

*For testing*, we recommend that you use a self-signed SHA-256 with ECDSA code-signing certificate.  To create a code signing certificate, install OpenSSL (https://www.openssl.org/) on your machine.  After you install OpenSSL, make sure that openssl is assigned to the OpenSSL executable in your command prompt or terminal environment.

The implementation of openssl on MacOS is a bit different than Linux. Please use those distributions based on Linux, like Ubuntu, Debian or Amazon Linux.

### Get A certificate and A private key

In your working directory, use the following text to create a file named cert_config.txt. Replace test_signer@amazon.com with your email address:

```
[ req ]
prompt = no
distinguished_name = my_dn

[ my_dn ]
commonName = test_signer@amazon.com

[ my_exts ]
keyUsage = digitalSignature
extendedKeyUsage = codeSigning

```

### Create an ECDSA code-signing private key:

```
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform PEM -out ecdsasigner.key 
```

### Create an ECDSA code-signing certificate:

```
$ openssl req -new -x509 -config cert_config.txt -extensions my_exts -nodes -days 365 -key ecdsasigner.key -out ecdsasigner.crt
```

*We will use the private key (ecdsasigner.key) to sign the code file and get a signature file.  We will put the certificate (ecdsasigner.crt) into the device code to verify the digitally signed file.*


### Create a signature:

```
$ openssl dgst -sha256 -sign ecdsasigner.key "your-code-file" > signature.der
```

### Convert binary to base64 encoded string:

```
$ base64 signature.der
```

This command displays an base64 encoded signature.  Its length is 96 bytes.  

## Put the certificate into device code

Use the [PEMfileToCString.html](http://htmlpreview.github.io/?https://github.com/aws/amazon-freertos/blob/master/tools/certificate_configuration/CertificateConfigurator.html) to convert your certificate into a C string and replace the string in *codesigner_certificate.h*.