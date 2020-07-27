# Code signing & verification User Manual

This project provide the code of a function (`aws_iot_check_signature`) for verifying the digital signature of files that have been signed by using the service of Code Signing for AWS IoT.

## What is code signing & verification for AWS IoT?

### Code signing

Code Signing for AWS IoT is documented here:

https://docs.aws.amazon.com/signer/latest/developerguide/Welcome.html

To get started with *Code Signing for AWS IoT*, please follow the instructions here:

https://docs.aws.amazon.com/signer/latest/developerguide/gs-toplevel.html

### SIGNATURE verification

Once you’ve signed a file, there will be a ***signature*** for verifying the file’s authenticity.  

If you use AWS IoT to deliver the file and the signature to the device, it’s the responsibility of your device firmware to verify the signature of the received file. The signature is usually delivered inside of an [AWS IoT Job document](https://docs.aws.amazon.com/iot/latest/developerguide/iot-jobs.html), as the value of the *`codesign`* property.  

## Getting Started

### Getting source code

```
cd ~
git clone https://github.com/aws-samples/aws-iot-code-verify.git
```

### Getting mbedTLS

```
cd aws-iot-code-verify
wget -qO- https://github.com/ARMmbed/mbedtls/archive/mbedtls-2.18.1.tar.gz | tar xvz -C external_libs/mbedTLS --strip-components=1
wget -qO- https://github.com/ARMmbed/mbed-crypto/archive/mbedcrypto-1.1.1.tar.gz | tar xvz -C external_libs/mbedTLS/crypto --strip-components=1`
cd external_libs/mbedTLS && make -j2
cd ../..
```

### Preparing code file and signature

This topic describes how to create your own code file and sign it digitally. For more information on how to process, see [here](https://docs.aws.amazon.com/signer/latest/developerguide/gs-toplevel.html)

We recommend to use above method, but there is another optional way to do so for convenience, it's self-sign.
1. Put the downloaded file(to be verified) under the example directory.
2. Edit `codesigner_certificate.h` and fill in your signing certificate into `signingcredentialSIGNING_CERTIFICATE_PEM`.  Refer to the "Put the certification into device code" section in the Self-Sign Guide.
3. Edit `verification_sample.c` and fill in the `SIGNATURE_IN_BASE64` and `DOWNLOADED_FILE_NAME`, also the `FILE_SIZE_IN_BYTES`.  Refer to "Create an signature" in Self-sign Guide.

Build the verification sample app:

```
make -j2
```
>For a quick start, this project has provide an example that has been digitally signed using Code Signing for AWS IoT, as well as the corresponding signature.  The example file is located in `demo` git branch.  

### Verification

You can run the sample application, verification_sample, directly on your **Linux** machine:

```
./verification_sample
```


Note:

MacOS 10.14 and later is not supported due to the change to LibreSSL, a version of the TLS/crypto stack forked from OpenSSL in 2014 from the latest version of High Sierra (10.13.3).

A successful verification job displays output like the following. Some lines in this example have been removed from the listing for brevity.

```
$ ./verification_sample
verification start.
decoded signature is: 0D g.�������L��G��:����?Y�͆�d &�jH�S&rS���`   |:j�c��dQ�{�t� and length is 70
CRYPTO_SignatureVerificationStarted
CRYPTO_SignatureVerificationUpdated
CRYPTO_SignatureVerificationFinal
Verify OK.
verification finish.
```

## Wrapper layer
This project provides wrapper functions for adapting to underlying platform APIs for printing logs. The wrappers are defined in include/aws_iot_wrapper.h.  You can modify it for your platform’s logging system.

## Limitations

This project requires the mbedTLS crypto library, it is an implementation of the [TLS and SSL](https://en.wikipedia.org/wiki/Transport_Layer_Security) protocols.  The respective cryptographic algorithms and support code from mbedTLS are required.

This project supports SHA256-ECDSA hash algorithm and encryption algorithm, which is one of the signing platforms available in Code Signing for AWS IoT service.  Another hash algorithm and encryption algorithm supported by AWS is SHA1-RSA, which is not as strong as SHA256-ECDSA.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

