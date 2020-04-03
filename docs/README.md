
# Porting guide to enable OPTIGA™ Trust M on your MbedTLS package 
This document guides to port the mbeTLS software crypto library functions
to use OPTIGA™ Trust M hardware secure element based cryptographic functionalities.
 

# Table of contents
1. [About this Document](#introduction) 
2. [OPTIGA™ Trust M Integration to mbedTLS](#paragraph2)<br>
    2.1 [Initialization API's](#initialization)<br>
    2.2 [Cryptographic API's](#Cryptofunctions)<br>
   
## 1. About this Document <a name="introduction"></a>
The aim of this document is to describe the porting details of OPTIGA™ Trust M into mbedTLS software crypto library on any hardware platform (e.g. microcontroller,
single board computer, PC etc..) mbedTLS is a crypto library used in FreeRTOS to perform TLS Handshke (secure channel establishment). This library uses an interface, which allows to substitute some of it's functionality by third-party crypto implemementations. Trust M substitutes standard software crypto implemementation for FreeRTOS/mbedTLS for such functions as: ECDSA, ECDHE, RSA.

### 2. OPTIGA™ Trust M Integration to mbedTLS<a name="subparagraph1"></a>

The functions that are needed to be integrated to mbedTLS are defined below.<br>

#### 2.1 Initialization API's <a name="initialization"></a>

- These are the API's which initialises the OPTIGA™ Trust M chip.
- Create these API's in the file “optiga_trust_m.c” and update corresponding header file. Copy these files under folder  [optiga](https://github.com/Infineon/optiga-trust-m/tree/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga)

    - [static volatile optiga_lib_status_t optiga_lib_status]()<br>
        This static variable will be used to store call back status.
    - [static void optiga_util_callback(void * context, optiga_lib_status_t return_status)]()<br>
    This is used as call back function to return the API execution status after the operation is completed
    asynchronously.

    - [void read_certificate_from_optiga(char * cert_pem, uint16_t * cert_pem_length)]()<br>
    This API reads DER encoded device certificate stored in OPTIGA™ security chip and converts to PEM encoding
format.

   - [void read_trust_anchor_from_optiga(uint16_t oid, char * cert_pem, uint16_t * cert_pem_length)]()<br>
   This API reads the data from trust anchor oid.
   
   - [static void write_optiga_trust_anchor(void)]()<br>
   This API writes the trust anchor to OPTIGA™ trust anchor OID.

    - [static void write_data_object (uint16_t oid, const uint8_t * p_data, uint16_t
    length)]()<br>
        This API writes the device certificate given as input to the specified oid in the OPTIGA™ security chip.


    - [void optiga_trust_init(void)]()<br>
    This API initializes the OPTIGA™ security chip by calling the open application. It also must write the device
    certificate to the Security chip.

    For more information refer [example_optiga_util_read_data.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_util_read_data.c) and [example_optiga_util_write_data.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_util_write_data.c)

#

#### 2.2 Cryptographic API's <a name="Cryptofunctions"></a>


- #### ECDH
    This section explains about porting of ECDH key pair geneartion and shared secret computation API's.<br>
    Create all the below mentioned APIs in  “trustm_ecdh.c” file and move file under directory [mbedTLSPort](https://github.com/Infineon/optiga-trust-m/tree/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port).
    Entire “trustm_ecdh.c” file must be guarded under
    macro [MBEDTLS_ECDH_C](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdh.c/#L31)<br>
  
    - [#define OPTIGA_TRUSTM_KEYID_TO_STORE_SHARED_SECRET  0xE103](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdh.c/#L49)
    <br>This macro defines the session oid used to store shared secret genearted
    - [static void    optiga_lib_status_crypt_event_completed_status;](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdh.c/#L49)<br>
        This static variable will be used to store call back status.


   -  [static void optiga_crypt_event_completed(void * context, optiga_lib_status_t
    return_status)](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdh.c/#L52-L59) <br> 
        The above function used as a call back function to return the API execution status after the operation is completed
        asynchronously.

   
    - [int mbedtls_ecdh_gen_public(mbedtls_ecp_group *grp, mbedtls_mpi
    *d,mbedtls_ecp_point *Q, int (*f_rng)(void *, unsigned char *, size_t), void
    *p_rng)](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdh.c/#L65-L130)<br>  
       -  This API generates ECC key pair using OPTIGA™ Security chip and stores the private key in the security
    chip and returns only the public key. The returned public key need to be stored into the mbedtls
    structure.<br>
        - This API need to be defined under the macro [MBEDTLS_ECDH_GEN_PUBLIC_ALT](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdh.c/#L61). By default the above
    API is implemented in “ESP_IDF\components\mbedtls\mbedtls\library\ecdh.c” file for software crypto
    operation. The software implementation of above API need to be guarded under macro as below
    #ifdef !MBEDTLS_ECDH_GEN_PUBLIC_ALT
    
    - [int mbedtls_ecdh_compute_shared(mbedtls_ecp_group *grp, mbedtls_mpi *z,const
    mbedtls_ecp_point *Q, const mbedtls_mpi *d, int (*f_rng)(void *, unsigned char *,
    size_t), void *p_rng)](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdh.c/#L138-L237)
    
        - This API computes shared secret using OPTIGA™ Security chip and returns the shared. This returned
    shared secret need to be stored into the mbedtls structure.
         - This API need to be defined under the
    macro [MBEDTLS_ECDH_COMPUTE_SHARED_ALT](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdh.c/#L134).
      - By default the above API is implemented under
    “ESP_IDF_PATH\components\mbedtls\mbedtls\library\ecdh.c” file for software crypto operation. This software
    implementation of above API need to be guarded under macro as below
    #ifdef ! MBEDTLS_ECDH_COMPUTE_SHARED_ALT

    For more information about OPTIGA™ Trust M Key generation and shared secret operation refer [example_optiga_crypt_ecdh.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_crypt_ecdh.c)


#
- #### ECDSA <br>
    This section explains about porting of ECDSA sign and ECDSA verify API's. <br>
    Create all the below mentioned APIs in  “trustm_ecdsa.c” file and move file under [mbedTLSPort](https://github.com/Infineon/optiga-trust-m/tree/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port). Entire “trustm_ecdsa.c” file must be guarded under
    macro
    [MBEDTLS_ECDSA_C](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdsa.c/#29)<br>
    
     
    - [static void optiga_lib_status_t crypt_event_completed_status;](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdsa.c/#L45)<br>
  This static variable will be used to store call back status.
   
    - [static void optiga_crypt_event_completed(void * context, optiga_lib_status_t
    return_status)](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdsa.c/#L45-L55)<br>  This is used as callback function to return the API execution status after the operation is completed
        asynchronously.

   -  [int mbedtls_ecdsa_sign( mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi
    *s,const mbedtls_mpi *d, const unsigned char *buf, size_t blen, int (*f_rng)(void
    *, unsigned char *, size_t), void *p_rng )](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdsa.c/#L58-L136)<br>
        - This API generates ECC Signature using ECC private key stored in OPTIGA™ Security chip for the given input and returns the generated   signature. This generated signature need to be stored into the mbedtls structure.
        - This API need to be defined under the macro
    [MBEDTLS_ECDSA_SIGN_ALT](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdsa.c/#L57)
      - By default the above API is implemented under
    “ESP_IDF_PATH\components\mbedtls\mbedtls\library\ecdsa.c” file for software crypto operation.This software implementation of above API need to be guarded under macro as below #ifdef ! MBEDTLS_ECDSA_SIGN_ALT
    
    
   -  [int mbedtls_ecdsa_verify( mbedtls_ecp_group *grp,const unsigned char *buf, size_t
    blen, const mbedtls_ecp_point *Q, const mbedtls_mpi *r, const mbedtls_mpi *s)](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdsa.c/#L140-L277)<br>
    
        - This API verifies ECC Signature using OPTIGA™ Security chip for the given input public key, input data and signature.This API need to be defined under the macro [MBEDTLS_ECDSA_VERIFY_ALT](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port/trustm_ecdsa.c/#L139).
        - By default the above API is implemented under
        “ESP_IDF\components\mbedtls\mbedtls\library\ecdsa.c” file for software crypto operation.This software
        implementation of above API need to be guarded under macro as below
        #ifdef ! MBEDTLS_ECDSA_VERIFY_ALT`
        
         For more information about OPTIGA™ Trust M Key generation and shared secret operation refer [example_optiga_crypt_ecdsa_sign.c ](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_crypt_ecdsa_sign.c) and [example_optiga_crypt_ecdsa_verify.c ](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_crypt_ecdsa_verify.c)
         
#
- #### RSA <br>

    This section explains about porting of RSA sign,verify,encrypt,decrypt API's<br>
    Copy the mbedTLS rsa file from folder "ESP_IDF_PATH\components\mbedtls\mbedtls\rsa.c" to the directory [mbedTLSPort](https://github.com/Infineon/optiga-trust-m/tree/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/mbedtls_port). Rename the file to “trustm_rsa.c”. Entire “trustm_rsa.c” file must be guarded under macro [MBEDTLS_RSA_ALT](C:\AzureEsp32\EspAzure\esp-idf\components\optiga\examples\integration\mbedtls\trustm_rsa.c\#L58)<br>
   

    - [#define TRUSTM_RSA_1024_KEYSIZE (0x0080)]()<br>
    This macro defines the key size for RSA 1024
    - [#define TRUSTM_RSA_2048_KEYSIZE (0x0100)]()<br>
    This macro defines the key size for RSA 2048
    - [#define TRUSTM_RSA_PUBLIC_KEY_MAX_SIZE (300)]()<br>
    This macro defines the Max Public key size considering RSA 2048.
    - [#define TRUSTM_RSA_SIGNATURE_LEN_MAX_SIZE (300)]()<br>
    This macro defines the maximum signature size considering RSA 2048.
    - [#define TRUSTM_RSA_NEGATIVE_INTEGER (0x7F)]()<br>
        This macro defined to identify the negative integer
    - [define TRUSTM_RSA_PRIVATE_KEY_OID (0xE0FC)]()<br>
    This macro defines the RSA private key in OPTIGA used during RSA sign and decrypt
    - [#define TRUSTM_RSA_SET_DER_LENGTH(buffer, index, value)]()<br>
    This macro to add the value to the buffer at provided index.
    - [#define TRUSTM_RSA_CHECK_MODULUS_FIRST_BYTE_NEGATIVE(value)]()<br>
    This macro checks whether modulus is negative or not
    - [#define TRUSTM_RSA_GET_LENGTH_FIELD_INBYTES(value)]()<br>
    This macro defines length field required for DER BIT STRING for RSA 1024 and 2048 <br>
      
    - [static volatile optiga_lib_status_t crypt_event_completed_status;]()<br>
    This static variable will be used to store call back status.
    
    - [static void optiga_crypt_event_completed(void * context, optiga_lib_status_t
    return_status)]()<br>
    This is used as call back function to return the API execution status after the operation is completed
    asynchronously.
    
    - [static void mbedtls_rsa_create_public_key_bit_string_format( const uint8_t *
    n_buffer,uint16_t n_length, const uint8_t * e_buffer, uint16_t e_length,
    uint8_t * key_buffer, uint16_t * key_length)]()<br>
    This function forms the public key in DER BIT STRING format.
    
    - [static int mbedtls_rsa_get_sig_scheme_digest_len(mbedtls_md_type_t md_alg,optiga_rsa_signature_scheme_t * signature_scheme, uint8_t *
    digest_length)]()<br>
    This function used to get signature algorithm and digest length based on the hash algorithm.
    
    - [static int mbedtls_rsa_get_sig_len_key_type(uint16_t modulus_length,uint16_t * signature_length, uint8_t * key_type)]()<br>
    This function used to get signature length and key type based on modulus length.
    - [int mbedtls_rsa_rsassa_pkcs1_v15_verify( mbedtls_rsa_context *ctx, int
    (*f_rng)(void *, unsigned char *, size_t), void *p_rng, int mode,
    mbedtls_md_type_t md_alg, unsigned int hashlen, const unsigned char *hash,
    const unsigned char *sig )]()<br>
    This API verifies the signature using OPTIGA™ security chip using the public key.
     ```sh       
    Note :
    - If Azure Certificate chain has RSA 4096 certificate, certificate path validation has to be disabled since OPTIGA™ Trust M supports only RSA 1024 and 2048.
    - Disabling of certificate path validation can be done by updating "mbedtls_ssl_conf_authmode(&tls->conf, MBEDTLS_SSL_VERIFY_NONE)" in function "static esp_err_t  set_ca_cert(esp_tls_t *tls, const unsigned char *cacert, size_t cacert_len)" in file esp_tls.c present under “ESP_IDF_PATH\components\esptls”
    
    ```
    - [int mbedtls_rsa_rsassa_pkcs1_v15_sign( mbedtls_rsa_context *ctx,int (*f_rng)
    (void *, unsigned char *, size _t), void *p_rng, int mode, mbedtls_md_type_t
    md_alg, unsigned int hashlen, const unsigned char *hash, unsigned char *sig
    )]()<br>
    This API generates signature for the given digest using the RSA private key stored in OPTIGA™ security
    chip and the signature generated need to be stored in the mbedTLS signature structure.
    
    - [int mbedtls_rsa_rsaes_pkcs1_v15_encrypt( mbedtls_rsa_context *ctx, int
    (*f_rng)(void *, unsigned char *, size_t),void *p_rng,int mode, size_t
    ilen,const unsigned char *input, unsigned char *output )]()<br>
    This API encrypts the input message using OPTIGA™ security chip.
    
    - [int mbedtls_rsa_rsaes_pkcs1_v15_decrypt( mbedtls_rsa_context *ctx, int
    (*f_rng)(void *, unsigned char *, size_t), void *p_rng, int mode, size_t
    *olen,const unsigned char *input, unsigned char *output, size_t
    output_max_len )]()<br>
    This API decrypts the message using the RSA private key stored in OPTIGA™ security chip.<br>
    
    For more information refer [example_optiga_crypt_rsa_sign.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_crypt_rsa_sign.c), [example_optiga_crypt_rsa_verify.c](https://github.com/Infineon/optiga-trust-m/blob/ae80dfe4b1ac35b5932644e783ff9d226ae266d9/examples/optiga/example_optiga_crypt_rsa_verify.c).
   
