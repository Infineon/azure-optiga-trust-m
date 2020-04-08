
# mbedTLS porting guide for OPTIGA™ Trust M 
This document guides to port the mbedTLS software crypto library functions
to use OPTIGA™ Trust M hardware secure element based cryptographic functionalities.
 

# Table of contents
-  [About this document](#introduction) 
- [OPTIGA™ Trust M integration to mbedTLS](#Integration)<br>
    - [Initialization API's](#initialization)<br>
    - [Cryptographic API's](#Cryptofunctions)<br>
   
## 1. About this document <a name="introduction"></a>
The aim of this document is to describe the porting details of OPTIGA™ Trust M into mbedTLS software crypto library on any hardware platform (e.g. microcontroller,
single board computer etc...).<br>
mbedTLS is a crypto library to perform TLS Handshke (secure channel establishment). This library uses an interface, which allows to substitute some of it's functionality by third-party crypto implemementations.For example mbedTLS used in FreeRTOS, where OPTIGA™ Trust M can be used to substitute the standard software crypto implemementation functions of ECDSA, ECDH and RSA.

## 2. OPTIGA™ Trust M integration to mbedTLS<a name="Integration"></a>

The functions that are needed to be integrated into mbedTLS are defined below.<br>

### 2.1 Initialization API's <a name="initialization"></a>

These are the API's which initializes the OPTIGA™ Trust M chip. Define these API's in the file “optiga_trust.c” and update corresponding header file. Copy these files under folder [utilities](https://github.com/Infineon/optiga-trust-m/tree/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/utilities)

- [static volatile optiga_lib_status_t optiga_lib_status](https://github.com/Infineon/optiga-trust-m/blob/677ca030d915962288c172bd287f8917518066f5/examples/utilities/optiga_trust.c/#L50)<br>Call back status is stored in this variable.
- [optiga_util_callback](https://github.com/Infineon/optiga-trust-m/blob/677ca030d915962288c172bd287f8917518066f5/examples/utilities/optiga_trust.c/#L51-L54)<br>
This is used as call back function to return the API execution status after the operation is completed
asynchronously.
- [read_certificate_from_optiga](https://github.com/Infineon/optiga-trust-m/blob/677ca030d915962288c172bd287f8917518066f5/examples/utilities/optiga_trust.c/#L65-L149)<br>
This API reads DER encoded device certificate stored in OPTIGA™ security chip and converts to PEM encoding
format.
- [read_trust_anchor_from_optiga](https://github.com/Infineon/optiga-trust-m/blob/677ca030d915962288c172bd287f8917518066f5/examples/utilities/optiga_trust.c/#L151-L237)<br>
This API reads the data from trust anchor oid.
- [write_optiga_trust_anchor](https://github.com/Infineon/optiga-trust-m/blob/677ca030d915962288c172bd287f8917518066f5/examples/utilities/optiga_trust.c/#L340-L557)<br>
This API writes the trust anchor to OPTIGA™ trust anchor OID.
- [write_data_object](https://github.com/Infineon/optiga-trust-m/blob/677ca030d915962288c172bd287f8917518066f5/examples/utilities/optiga_trust.c/#L239-L292)<br>
    This API writes the device certificate gives as an input to the specified oid in the OPTIGA™ security chip.
- [optiga_trust_init](https://github.com/Infineon/optiga-trust-m/blob/677ca030d915962288c172bd287f8917518066f5/examples/utilities/optiga_trust.c/#L586-L643)<br>
This API initializes the OPTIGA™ security chip by calling the open application. It also writes the device
certificate to the Security chip.
<br>

For more information refer to the [example_optiga_util_read_data.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_util_read_data.c) and [example_optiga_util_write_data.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_util_write_data.c)

#

### 2.2 Cryptographic API's <a name="Cryptofunctions"></a>


- #### ECDH
    This section explains about porting of ECDH key pair generation and shared secret computation API's.
    Entire “trustm_ecdh.c” file must be guarded under
    macro [MBEDTLS_ECDH_C](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdh.c/#L29)<br>
  
    - [#define OPTIGA_TRUSTM_KEYID_TO_STORE_PRIVATE_KEY  0xE103](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdh.c/#L42)
    <br>This macro defines the session oid used to store shared secret generated
    - [static void    optiga_lib_status_crypt_event_completed_status;](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdh.c/#L47)<br>
        This static variable will be used to store call back status.
    - [optiga_crypt_event_completed](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdh.c/#L50-L57) <br> 
        The above function used as a call back function to return the API execution status after the operation is completed
        asynchronously.  
    - [mbedtls_ecdh_gen_public](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdh.c/#L63-L134)<br>  
        -  This API generates ECC key pair using OPTIGA™ Security chip, stores the private key in the security chip and returns only the public key. The returned public key need to be stored into the mbedtls
        structure.<br>
        - This API need to be defined under the macro [MBEDTLS_ECDH_GEN_PUBLIC_ALT](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdh.c/#L59).
    
    - [mbedtls_ecdh_compute_shared](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdh.c/#L141-L243)
    
        - This API computes shared secret using OPTIGA™ Security chip and returns the shared. This returned
        shared secret need to be stored into the mbedtls structure.
        - This API need to be defined under the
        macro [MBEDTLS_ECDH_COMPUTE_SHARED_ALT](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdh.c/#L137).
     <br>

    For more information about OPTIGA™ Trust M Key generation and shared secret operation refer [example_optiga_crypt_ecdh.c](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/optiga/example_optiga_crypt_ecdh.c)


#
- #### ECDSA <br>
    This section explains about porting of ECDSA sign and ECDSA verify API's. Entire “trustm_ecdsa.c” file must be guarded under
    macro
    [MBEDTLS_ECDSA_C](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdsa.c/#L29)<br>
    - [static void optiga_lib_status_t crypt_event_completed_status;](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdsa.c/#L48)<br>
  This static variable will be used to store call back status.
    - [optiga_crypt_event_completed](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdsa.c/#L51-L58)<br>  This is used as callback function to return the API execution status after the operation is completed
        asynchronously.
    - [mbedtls_ecdsa_sign](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdsa.c/#L61-L151)<br>
        - This API generates ECC Signature using ECC private key stored in OPTIGA™ Security chip for the given input and returns the generated   signature. This generated signature need to be stored into the mbedtls structure.
        - This API need to be defined under the macro
    [MBEDTLS_ECDSA_SIGN_ALT](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdsa.c/#L60)
    - [mbedtls_ecdsa_verify](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdsa.c/#L154-L289)<br>
    
        - This API verifies ECC Signature using OPTIGA™ Security chip for the given input public key, input data and signature.This API need to be defined under the macro [MBEDTLS_ECDSA_VERIFY_ALT](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_ecdsa.c/#L153).
        <br>

    For more information about OPTIGA™ Trust M Key generation and shared secret operation refer [example_optiga_crypt_ecdsa_sign.c ](hhttps://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/optiga/example_optiga_crypt_ecdsa_sign.c) and [example_optiga_crypt_ecdsa_verify.c ](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/optiga/example_optiga_crypt_ecdsa_verify.c)
         
#
- #### RSA <br>

    This section explains about porting of RSA sign,verify,encrypt,decrypt API's. Entire “trustm_rsa.c” file must be guarded under macro [MBEDTLS_RSA_ALT](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c\#L32)<br>

    - [define TRUSTM_RSA_PRIVATE_KEY_OID (0xE0FC)](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L79)<br>
    This macro defines the RSA private key inOPTIGA™ Trust M used during RSA sign and RSA decrypt.
    - [static volatile optiga_lib_status_t crypt_event_completed_status;](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L98)<br>
    This static variable will be used to store call back status.
    - [optiga_crypt_event_completed](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L114-L121)<br>
    This is used as call back function to return the API execution status after the operation is completed
    asynchronously.
    - [mbedtls_rsa_create_public_key_bit_string_format](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L123-L186)<br>
    This function forms the public key in DER BIT STRING format.
    - [mbedtls_rsa_get_sig_scheme_digest_len)](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L188-L223)<br>
    This function used to get signature algorithm and digest length based on the hash algorithm.
    - [mbedtls_rsa_get_sig_len_key_type](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L225-L260)<br>
    This function used to get signature length and key type based on modulus length.
    - [mbedtls_rsa_rsassa_pkcs1_v15_verify](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L2246-L2380)<br>
    This API verifies the signature using OPTIGA™ security chip using the public key.
    
            Note :
            - If Azure Certificate chain has RSA 4096 certificate, certificate path validation has to be disabled since OPTIGA™ Trust M supports only RSA 1024 and 2048.
            - If user is using ESP IDF then Disabling of certificate path validation can be done by updating "mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE)" in function "static esp_err_t  set_ca_cert(esp_tls_t *tls, const unsigned char *cacert, size_t cacert_len)" in file esp_tls.c present under “ESP_IDF_PATH\components\esptls”
    
    - [mbedtls_rsa_rsassa_pkcs1_v15_sign](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L1908-L2016)<br>
    This API generates signature for the given digest using the RSA private key stored in OPTIGA™ security
    chip and the signature generated need to be stored in the mbedTLS signature structure.
    - [mbedtls_rsa_rsaes_pkcs1_v15_encrypt](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L1374-L1487)<br>
    This API encrypts the input message using OPTIGA™ security chip.
    - [mbedtls_rsa_rsaes_pkcs1_v15_decrypt](https://github.com/Infineon/optiga-trust-m/blob/d15dd7a0b4e23f2adac6cbd2cd0f924d0ab03197/examples/mbedtls_port/trustm_rsa.c/#L1674-L1733)<br>
    This API decrypts the message using the RSA private key stored in OPTIGA™ security chip.<br>

    For more information refer [example_optiga_crypt_rsa_sign.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_crypt_rsa_sign.c) , [example_optiga_crypt_rsa_verify.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_crypt_rsa_verify.c) , [example_optiga_crypt_rsa_encrypt_message.c](https://github.com/Infineon/optiga-trust-m/blob/347a240d1e186ae8f0b264da78c106d8d622aa13/examples/optiga/example_optiga_crypt_rsa_encrypt_message.c) , 
    [example_optiga_crypt_rsa_decrypt.c](https://github.com/Infineon/optiga-trust-m/blob/347a240d1e186ae8f0b264da78c106d8d622aa13/examples/optiga/example_optiga_crypt_rsa_decrypt.c) .
   
