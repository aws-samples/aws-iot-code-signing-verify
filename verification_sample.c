/*
 * Copyright (C) 2019-2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>

#include "aws_iot_wrapper.h"

#include "mbedtls/base64.h"
#include "aws_iot_verify.h"

#define MAX_SIZE_OF_SIGNATURE   96                  //length of base64 encoded signature
#define MAX_SIZE_OF_SIGNALGO    16                  //max length of signature algorithm
#define SIGNATURE_IN_BASE64     ""                  //Paste code signature here 
#define SIGNATURE_ALGORITHM     "SHA256withECDSA"   //hash and encryption algorithm
#define DOWNLOADED_FILE_NAME    ""                  //downloaded file( code ) name
#define FILE_SIZE_IN_BYTES      0                   //allocated memory size to read file

/*
 * read file form file system or flash
 * need implement customer read block code.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>


int main( int argc, char **argv ) {

    int rc = SUCCESS;

    IOT_INFO( "verification start." );
    /*
     * Assume you already downloaded the file and got signature
     * and signature Algorithm from job file, like this:
     * {
     *  "signature": "MEQCIGcdLoakw....6aqNj2OunZFGbe9Z0jQ==",
     *  "signatureAlgorithm": "SHA256withECDSA",
     *  "fileSize": 36
     *  }
     *  PS: you need parsing the JSON format job file in real world.
     */

    /*
     * base64 encoded signature
     */
    char signature[MAX_SIZE_OF_SIGNATURE + 1] = SIGNATURE_IN_BASE64;
    /*
     * sha256 and ecdsa algorithm for hashing and signing
     */
    char signAlgo[MAX_SIZE_OF_SIGNALGO + 1] = SIGNATURE_ALGORITHM;
     /*
     * file name in string
     */
    const char * fileName = DOWNLOADED_FILE_NAME;
    if( fileName == "" )
    {
        IOT_ERROR( "File name in string cannot be NULL." );
        return FAILURE;
    }
    /*
     * file size in byte
     */
    uint32_t payloadSize = FILE_SIZE_IN_BYTES;
    if( payloadSize == 0 )
    {
        IOT_ERROR( "File length in byte cannot be zero." );
        return FAILURE;
    }

    /*
     * read file from file system or flash
     */
    char *payloadBuffer = ( char * ) calloc( payloadSize, sizeof( char ) );
    if ( payloadBuffer == NULL ) 
    {
        IOT_ERROR( "Don't have enough memory for payload." );
        return FAILURE;
    }

    /*
     * need implement customer read block code!
     */
#if defined ( __APPLE__ ) || ( __linux__ ) || ( __unix__ )
    int fd = open( fileName, O_RDWR | O_CREAT, 0666 );

    if ( fd == -1 )
    {
        IOT_ERROR( "Cannot open test file." );
        free( payloadBuffer );
        return FAILURE;
    }

    read( fd, payloadBuffer, payloadSize ); 

    close( fd );
#else
    #error "Implement your read block code here!"
#endif

    /*
     * signature buffer
     */
    uint8_t * signatureBuffer = ( uint8_t * ) malloc( MAX_SIZE_OF_SIGNATURE );
    if ( signatureBuffer == NULL ) 
    {
        IOT_ERROR( "Don't have enough memory for signature." );
        free( payloadBuffer );
        return FAILURE;
    }
    size_t signatureLen;
    /*
     * decode signature from base64 format to binary
     */
    rc = mbedtls_base64_decode( signatureBuffer, MAX_SIZE_OF_SIGNATURE, \
                            &signatureLen, signature, MAX_SIZE_OF_SIGNATURE );

    if ( SUCCESS != rc ) 
    {
        IOT_ERROR( "Base64 decode fail, ignore this file. error : %d ", rc );
        free( payloadBuffer );
        free( signatureBuffer );
        return FAILURE;
    }
    else
    {
        IOT_INFO( "decoded signature is: %s and length is %d", signatureBuffer, ( int )signatureLen );
    }

    /*
     * check the file signature and return the result
     * it is the core function for code verification
     */
    rc = aws_iot_check_signature( payloadBuffer, payloadSize, \
                                    signatureBuffer, signatureLen );

    if ( SUCCESS != rc ) 
    {
        IOT_ERROR( "Verification fail, ignore this file." );
    }
    else
    {
        IOT_INFO( "Verification finish." );
    }
    
    free( payloadBuffer );
    free( signatureBuffer );
    return rc;
}
