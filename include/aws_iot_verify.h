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

#ifndef __AWS_IOT_VERIFY_H__
#define __AWS_IOT_VERIFY_H__

#include "aws_iot_wrapper.h"

#define SUCCESS     0
#define FAILURE     -1


/* A composite cryptographic signature structure able to hold our largest supported signature. */

/**
 * @brief Commonly used buffer sizes for storing cryptographic hash computation
 * results.
 */
#define cryptoSHA1_DIGEST_BYTES      20
#define cryptoSHA256_DIGEST_BYTES    32

/**
 * @brief Library-independent cryptographic algorithm identifiers.
 */
#define cryptoHASH_ALGORITHM_SHA1           1
#define cryptoHASH_ALGORITHM_SHA256         2
#define cryptoASYMMETRIC_ALGORITHM_RSA      1
#define cryptoASYMMETRIC_ALGORITHM_ECDSA    2

/**
 * @brief Start a verification for a single file(code).
 *
 * @note This function check the signature of a file and 
 *       return the verification result immediately, SUCCESS
 *       or FAILURE.
 *      
 * @param[in] pbuf pointer to payload buffer for file(code).
 *            User need to allocate enough memory for the whole file.
 * @param[in] plen payload length in bytes. The value should be
 *            the same as the size of downloaded file.
 * @param[in] sbuf pointer to signature buffer for file(code).
 *            user need to allocate enough memory for signature.
 *            Signature should be in binary format, otherwise user 
 *            need to translate to binary format by themself. Please
 *            take the sample code as reference.
 * @param[in] slen signature length in bytes.
 * 
 * @return SUCCESS(0), or FAILURE(-1).
 */
int aws_iot_check_signature( unsigned char *pbuf, size_t plen, unsigned char *sbuf, size_t slen );

#endif /* ifndef __AWS_IOT_VERIFY_H__ */
