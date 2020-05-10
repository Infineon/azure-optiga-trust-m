/**
 * MIT License
 *
 * Copyright (c) 2019 Infineon Technologies AG
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
 * SOFTWARE
 *
 * @{
 */
 
#include <stdio.h>
#include "driver/uart.h"
#include "optiga/optiga_crypt.h"
#include "optiga/common/optiga_lib_logger.h"
#include "mbedtls/base64.h"

void pal_os_timer_delay_in_milliseconds(uint16_t milliseconds);
extern void write_data_object (uint16_t oid, const uint8_t * p_data, uint16_t length);

#define ECHO_TEST_TXD  (UART_PIN_NO_CHANGE)
#define ECHO_TEST_RXD  (UART_PIN_NO_CHANGE)
#define ECHO_TEST_RTS  (UART_PIN_NO_CHANGE)
#define ECHO_TEST_CTS  (UART_PIN_NO_CHANGE)

#define BUF_SIZE (1024)

#define CERTIFICATE 	"-----BEGIN CERTIFICATE-----\r\n"\
						"MIIB/DCCAaKgAwIBAgIJALMKa9w3lJTkMAoGCCqGSM49BAMCMFkxCzAJBgNVBAYT\r\n"\
						"AklOMQwwCgYDVQQIDANLQVIxDTALBgNVBAcMBEJBTkcxDTALBgNVBAoMBElGSU4x\r\n"\
						"DDAKBgNVBAsMA0RTUzEQMA4GA1UEAwwHQXp1cmVDQTAeFw0yMDAyMTcwOTM4Mzha\r\n"\
						"Fw0yMTAyMTYwOTM4MzhaMFkxCzAJBgNVBAYTAklOMQwwCgYDVQQIDANLQVIxDTAL\r\n"\
						"BgNVBAcMBEJBTkcxDTALBgNVBAoMBElGSU4xDDAKBgNVBAsMA0RTUzEQMA4GA1UE\r\n"\
						"AwwHQXp1cmVDQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLqrHZbGfOUKlfW8\r\n"\
						"sHENpzBLf6uMeYKDp/0sPrqwY9Lk0ehMBQkB3uHSIWHP3H0TlqLqZvSgDQV5ncG7\r\n"\
						"Myr1/wajUzBRMB0GA1UdDgQWBBR8+Il4IuRy8lWzwyPuWHnodVplFDAfBgNVHSME\r\n"\
						"GDAWgBR8+Il4IuRy8lWzwyPuWHnodVplFDAPBgNVHRMBAf8EBTADAQH/MAoGCCqG\r\n"\
						"SM49BAMCA0gAMEUCIEQ1JV1+Vhpu4XI7zYDMBKLSaphex/+sXB/h9KlNk1yRAiEA\r\n"\
						"gO9MFPaLum7e7HXvFgrx38mwiwWSMPMCf+AW5nJaHzU=\r\n"\
						"-----END CERTIFICATE-----\r\n"	

						
//#define CERTIFICATE	(0)

const unsigned char certificate [] = {CERTIFICATE};

void optiga_trust_init(void);

/**
 * Callback when optiga_crypt_xxxx operation is completed asynchronously
 */
optiga_lib_status_t crypt_event_completed_status;

static void optiga_crypt_event_completed(void * context, optiga_lib_status_t return_status)
{
	crypt_event_completed_status = return_status;
    if (NULL != context)
    {
        // callback to upper layer here
    }
}

/**
 * Convert PEM to DER format
 */
int convert_pem_to_der( const unsigned char *input, size_t ilen,
                        unsigned char *output, size_t *olen )
{
    int ret;
    const unsigned char *s1, *s2, *end = input + ilen;
    size_t len = 0;

    s1 = (unsigned char *) strstr( (const char *) input, "-----BEGIN" );
    if( s1 == NULL )
        return( -1 );

    s2 = (unsigned char *) strstr( (const char *) input, "-----END" );
    if( s2 == NULL )
        return( -1 );

    s1 += 10;
    while( s1 < end && *s1 != '-' )
        s1++;
    while( s1 < end && *s1 == '-' )
        s1++;
    if( *s1 == '\r' ) s1++;
    if( *s1 == '\n' ) s1++;

    if( s2 <= s1 || s2 > end )
        return( -1 );

    ret = mbedtls_base64_decode( NULL, 0, &len, (const unsigned char *) s1, s2 - s1 );
    if( ret == MBEDTLS_ERR_BASE64_INVALID_CHARACTER )
        return( ret );

    if( len > *olen )
        return( -1 );

    if( ( ret = mbedtls_base64_decode( output, len, &len, (const unsigned char *) s1,
                               s2 - s1 ) ) != 0 )
    {
        return( ret );
    }

    *olen = len;

    return( 0 );
}

/**
 * Generate ECC key pair
 */
int generatepublickey(optiga_ecc_curve_t curvetype)
{
	int ret = -1;
	optiga_key_id_t optiga_key_id = CONFIG_OPTIGA_TRUST_M_PRIVKEY_SLOT;
	optiga_crypt_t * me = NULL;
    optiga_lib_status_t command_queue_status = OPTIGA_CRYPT_ERROR;
    uint16_t i;
	uint8_t publickeygenerated[200];
	uint16_t len_of_publickey = sizeof(publickeygenerated);
	uint8_t temp_publickey[200];
	size_t temp_len_of_publickey;
	uint16_t offset_to_write = 0, offset_to_read = 0;
	uint16_t size_to_copy = 0;
	char public_key[200];
	uint16_t public_key_len;

	do
	{
		me = optiga_crypt_create(0, optiga_crypt_event_completed, NULL);
		if (NULL == me)
		{
			OPTIGA_CRYPT_LOG_MESSAGE ("optiga_crypt_create failed !!!");
            break;
		}

		crypt_event_completed_status = OPTIGA_LIB_BUSY;

		//invoke optiga command to generate a key pair.
		command_queue_status = optiga_crypt_ecc_generate_keypair(me, curvetype,
				(optiga_key_usage_t) (OPTIGA_KEY_USAGE_KEY_AGREEMENT
						| OPTIGA_KEY_USAGE_AUTHENTICATION),
				FALSE, &optiga_key_id, publickeygenerated, &len_of_publickey);

		if ( command_queue_status != OPTIGA_LIB_SUCCESS )
		{
			//optiga_crypt_ecc_generate_keypair api returns error !!!
			OPTIGA_CRYPT_LOG_MESSAGE ("optiga_crypt_ecc_generate_keypair api returns error !!!");
			break;
		}

		i=0;
		while (OPTIGA_LIB_BUSY == crypt_event_completed_status)
		{
			//Wait until the optiga_crypt_ecc_generate_keypair operation is completed
			i++;
			pal_os_timer_delay_in_milliseconds(30);
			if (i == 50)
				break;
		}

		if ( crypt_event_completed_status != OPTIGA_LIB_SUCCESS )
		{
			//optiga_util_open_application failed
			OPTIGA_CRYPT_LOG_MESSAGE ("optiga_util_open_application failed");
			break;
		}

		for(int k=0; k< len_of_publickey; k++)
		{			
			if((k%16) == 0)
			{
				printf("\n");
			}
			printf(" %02X", publickeygenerated[k]);
		}

		//convert to PEM format
        mbedtls_base64_encode((unsigned char *)temp_publickey, sizeof(temp_publickey),
                              &temp_len_of_publickey, publickeygenerated, len_of_publickey);

        memcpy(public_key, "-----BEGIN PUBLIC KEY-----\n", 28);
        offset_to_write += 28;
        
       
        //Properly copy key and format it as pkcs expects
        for (offset_to_read = 0; offset_to_read < temp_len_of_publickey;)
        {
            // The last block of data usually is less than 64, thus we need to find the leftover
            if ((offset_to_read + 64) >= temp_len_of_publickey)
                size_to_copy = temp_len_of_publickey - offset_to_read;
            else
                size_to_copy = 64;
            memcpy(public_key + offset_to_write, temp_publickey + offset_to_read, size_to_copy);
            offset_to_write += size_to_copy;
            offset_to_read += size_to_copy;
            public_key[offset_to_write] = '\n';
            offset_to_write++;
        }

        memcpy(public_key + offset_to_write, "-----END PUBLIC KEY-----\n\0", 26);

        public_key_len = offset_to_write + 26;
		
		//To print pem format public key
		printf("\nPEM format public key\n\n");
		for(i=0; i<public_key_len; i++)
        {
            printf("%c", public_key[i]);
        } 
		printf("\n");
		OPTIGA_CRYPT_LOG_MESSAGE ("Generate Key Pair successful!!!")
		
		ret = 0;
	}while(0);
	
	if (me)
    {
        optiga_crypt_destroy(me);
    }
	
	return ret;
}

/**
 * Write certficate to optiga
 */
int write_certificate(void)
{
	int ret;
	uint8_t certificate_buf[1300];
	size_t len_of_cert = sizeof(certificate_buf);
	
	ret = convert_pem_to_der( certificate, sizeof(certificate), (unsigned char*)certificate_buf, &len_of_cert);
	if(0 != ret)
	{
		return(-1);
	}
	
	for(int k=0; k < len_of_cert; k++)
    {
		if((k%16) == 0)
		{
			printf("\n");
		}
        printf(" %02X", certificate_buf[k]);		
    }
	
	printf("\n");
	
	write_data_object (CONFIG_OPTIGA_TRUST_M_CERT_SLOT, certificate_buf, len_of_cert);
	
	return 0;
	
}

static void optiga_personalization(void)
{	
    int ret = -1;
	optiga_ecc_curve_t curvetype;
	
    /* Configure parameters of an UART driver,
     * communication pins and install the driver */
    uart_config_t uart_config = {
        .baud_rate = 115200,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 122 ,
    };
    uart_driver_install(UART_NUM_0, BUF_SIZE * 2, 0, 0, NULL, 0);
    uart_param_config(UART_NUM_0, &uart_config);
    uart_set_pin(UART_NUM_0, ECHO_TEST_TXD, ECHO_TEST_RXD, ECHO_TEST_RTS, ECHO_TEST_CTS);

    uint8_t *data = (uint8_t *) malloc(BUF_SIZE);
	
	if(CERTIFICATE == 0)
	{
		printf("\nSelect the key type from below list\n");
		printf("Press 1 to Generate NIST P-256\n");
		printf("Press 2 to Generate NIST P-384\n");
		printf("Press 3 to Generate RSA 1024\n");
		printf("Press 4 to Generate RSA 2048\n");
			
		while (1) 
		{	
			// Read data from the UART
			int len = uart_read_bytes(UART_NUM_0, data, BUF_SIZE, 100/ portTICK_RATE_MS);
			// Write data back to the UART
			if(len > 0)
			{
				if('1' == (char)data[0])
				{				
					curvetype = OPTIGA_ECC_CURVE_NIST_P_256;
					printf("\nSelected NIST P-256 Curve\n");
					break;
				}
				else if('2' == (char)data[0])
				{
					curvetype = OPTIGA_ECC_CURVE_NIST_P_384;
					printf("\nSelected NIST P-384 Curve\n");
					break;
				}
				else if('3' == (char)data[0])
				{
					curvetype = OPTIGA_RSA_KEY_1024_BIT_EXPONENTIAL;
					printf("\nSelected RSA 1024\n");
					break;
				}
				else if('4' == (char)data[0])
				{
					curvetype = OPTIGA_RSA_KEY_2048_BIT_EXPONENTIAL;
					printf("\nSelected RSA 2048\n");
					break;
				}
				else
				{
					printf("Invalid option.Select any below option\n");
					printf("Press 1 to Generate NIST P-256\n");
					printf("Press 2 to Generate NIST P-384\n");
					printf("Press 3 to Generate RSA 1024\n");
					printf("Press 4 to Generate RSA 2048\n");
				}
			}
		}
		
		ret = generatepublickey(curvetype);
		if(0 != ret)
		{
			printf("\nGenerate Key Pair generation failed\n");
		}
	}
	else
	{
		ret = write_certificate();
		if(0 != ret)
		{
			printf("\nWrite certficate failed\n");
		}
	}
}

void app_main(void)
{
	optiga_trust_init();
	
	optiga_personalization();	
}
