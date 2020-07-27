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

/**
 * @file aws_iot_wrapper.h
 * @brief Logging and other macros for the SDK.
 * This file defines common logging macros with log levels to be used within the SDK.
 * These macros can also be used in the IoT application code as a common way to output
 * logs.  The log levels can be tuned by modifying the makefile.  Removing (commenting
 * out) the IOT_* statement in the makefile disables that log level.
 *
 * It is expected that the macros below will be modified or replaced when porting to
 * specific hardware platforms as printf may not be the desired behavior.
 */

#ifndef AWS_IOT_WRAPPER_H_
#define AWS_IOT_WRAPPER_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>

/**
 * @brief Debug level logging macro.
 *
 * Macro to expose function, line number as well as desired log message.
 */
#ifdef ENABLE_IOT_DEBUG
#define IOT_DEBUG( ... )    \
    {\
    printf( "DEBUG:   %s L#%d ", __func__, __LINE__ );  \
    printf( __VA_ARGS__ ); \
    printf( "\n" ); \
    }
#else
#define IOT_DEBUG( ... )
#endif

/**
 * @brief Debug level trace logging macro.
 *
 * Macro to print message function entry and exit
 */
#ifdef ENABLE_IOT_TRACE
#define FUNC_ENTRY    \
    {\
    printf( "FUNC_ENTRY:   %s L#%d \n", __func__, __LINE__ );  \
    }
#define FUNC_EXIT    \
    {\
    printf( "FUNC_EXIT:   %s L#%d \n", __func__, __LINE__ );  \
    }
#define FUNC_EXIT_RC( x )    \
    {\
    printf( "FUNC_EXIT:   %s L#%d Return Code : %d \n", __func__, __LINE__, x );  \
    return x; \
    }
#else
#define FUNC_ENTRY

#define FUNC_EXIT
#define FUNC_EXIT_RC( x ) { return x; }
#endif

/**
 * @brief Info level logging macro.
 *
 * Macro to expose desired log message.  Info messages do not include automatic function names and line numbers.
 */
#ifdef ENABLE_IOT_INFO
#define IOT_INFO( ... )    \
    {\
    printf( __VA_ARGS__ ); \
    printf( "\n" ); \
    }
#else
#define IOT_INFO( ... )
#endif

/**
 * @brief Warn level logging macro.
 *
 * Macro to expose function, line number as well as desired log message.
 */
#ifdef ENABLE_IOT_WARN
#define IOT_WARN( ... )   \
    { \
    printf( "WARN:  %s L#%d ", __func__, __LINE__ );  \
    printf( __VA_ARGS__ ); \
    printf( "\n" ); \
    }
#else
#define IOT_WARN( ... )
#endif

/**
 * @brief Error level logging macro.
 *
 * Macro to expose function, line number as well as desired log message.
 */
#ifdef ENABLE_IOT_ERROR
#define IOT_ERROR( ... )  \
    { \
    printf( "ERROR: %s L#%d ", __func__, __LINE__ ); \
    printf( __VA_ARGS__ ); \
    printf( "\n" ); \
    }
#else
#define IOT_ERROR( ... )
#endif

#ifdef __cplusplus
}
#endif

#endif // AWS_IOT_WRAPPER_H_
