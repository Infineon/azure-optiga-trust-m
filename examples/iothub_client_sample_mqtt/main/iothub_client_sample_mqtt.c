// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>

#include "iothub_client.h"
#include "iothub_device_client_ll.h"
#include "iothub_client_options.h"
#include "iothub_message.h"
#include "azure_c_shared_utility/threadapi.h"
#include "azure_c_shared_utility/crt_abstractions.h"
#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/shared_util_options.h"
#include "iothubtransportmqtt.h"
#include "iothub_client_options.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifdef MBED_BUILD_TIMESTAMP
    #define SET_TRUSTED_CERT_IN_SAMPLES
#endif // MBED_BUILD_TIMESTAMP

#ifdef SET_TRUSTED_CERT_IN_SAMPLES
    #include "certs.h"
#endif // SET_TRUSTED_CERT_IN_SAMPLES

/*String containing Hostname, Device Id & Device Key in the format:                         */
/*  "HostName=<host_name>;DeviceId=<device_id>;SharedAccessKey=<device_key>"                */
/*  "HostName=<host_name>;DeviceId=<device_id>;SharedAccessSignature=<device_sas_token>"    */
/*  "HostName=<host_name>;DeviceId=<device_id>;x509=true"                      */
#define EXAMPLE_IOTHUB_CONNECTION_STRING CONFIG_IOTHUB_CONNECTION_STRING

static const char* connectionString = EXAMPLE_IOTHUB_CONNECTION_STRING;

static char device_certificate_pem [1300] = {0};
static uint16_t device_certificate_pem_length = sizeof(device_certificate_pem);

#ifdef LOAD_TA_FROM_OPTIGA
//Read trust anchor from OPTIGA
static char trust_anchor_pem [1300] = {0};
static uint16_t trust_anchor_pem_length = sizeof(trust_anchor_pem);
#endif
const char *privatekey;

//Dummy private key assigned to allocate buffer
const char rsa1024privatekey[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIICXAIBAAKBgQDGwjZ8SoYeg9fGuDxewtytepXCwIEwU+b6GhYaEN18BkLaB5c9\r\n"
"PgldSXMf+H2T3WrM//Gqbe+3n9Ucl/NW0Xp++kBr6X3lqC/6uBQgPsXAbBitx0LM\r\n"
"EjhVsqJtGXMTtaIdaXbQAI5z8JQ9Mlh0wO8AE5ehfspTYlMT8PYcmtDkPQIDAQAB\r\n"
"AoGACH0c9Jv+NGlvGsadlXJ/GE2m/cVY/yZmNAJPNVfJDdX6nvM6C1yN69UKPLBR\r\n"
"NLJ9MDoyKRQ+67nA0VLQCsIxmA1yEwLVhpqMnmttttA1a90mhcOJ56IOZdz83u7Y\r\n"
"ltbW+wfTt8PFxLpCpeBf8T2YjOU/m3qnU6+nw37u1u76wgECQQDqIdKr1FmSurkE\r\n"
"C2Vyro6Kh3nmGZxGn/p/nFpZ26zYn4+abLDCEWpjv0dhiepvDqZWKUlhjaUi3Gs6\r\n"
"/h+YQKCBAkEA2VKZKGTpRqTRwBhBhtU+oiYzaqhNV0DtOkYDCv/JsZUWMe6hKmje\r\n"
"vl6YzCiqMMlZTRIVsIHiv48/juJTAAflvQJAZF3Hb72CAHJm6aLxBC5sEFpvGQKV\r\n"
"iXj+60FdQfP3ro0IBEzfoPHSR5wxv1Bd3OnMyFa+jEEqLz2KAin55UyfAQJATTlE\r\n"
"o034dtnqjtAPuNHdx9C7RJM5qF+x7JskSaxLB4dqs6OQMXnCbPNAaIuqrlteGDzs\r\n"
"6CO/Z0KH20YhKEmmIQJBAMRq1ErWYJ5MIYdbjOcBAFW6YxuHYdOpC+wAUjdp8EUk\r\n"
"uPkDQqwOHupUQcSc9yE1awcQOckamHFjUolF95RQz/c=\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

//Dummy private key assigned to allocate buffer
const char rsa2048privatekey[] =
"-----BEGIN RSA PRIVATE KEY-----\r\n"
"MIIEowIBAAKCAQEAyBGCGZOQ9lYTRsqtO5wYrqzxoMMI8T3bMjVOTuFR5LYXXpPB\r\n"
"sDYZFzC/9zfIlBC7eLz9VJbtD+WZO0iY/N49j9tpV30EapRCzc/hLHyvQlXLFVxd\r\n"
"JJ9C6USjeloUUSLgi96VAP6iFZp7BV8kb21J4Ky4VCse64ilRDvRDsiA4Va2b7Qt\r\n"
"EPhpdSyGZY8m+Rb3cLGSOD+K1ruYHMiMzwNTaBMLPfLqXXsgfSQGGIPmtY/pdBc9\r\n"
"pjCtZO3HDX429zE0XIG30dMK+iY/LzsNkXXP9WROfohOZ2bP0rIRDKza/Ys/wi1U\r\n"
"0CujKjIxvFMqxU51eQ8DrA2iF7uJsbN6L8w/qwIDAQABAoIBADx2fhj4rdCkhsLY\r\n"
"Ma5YKGVxwrxQ9PzjMsFjtrzD/5ndJgbhJKH6V27YvssZwrZssBt3EiBkVFR/kOWH\r\n"
"tSSGjZhSOO3FzHXhRKcqceSd8eFcSDm2ZjfRIcmZgsZRPt6eaboblHBug9F/lDo1\r\n"
"XK+IGdGaoUJencOU0k1ivnV3RuvSXg4HXXMDgxu866sXhdbvCzPVV+ho7FkNoK/w\r\n"
"tIgoDXQ8oQu2FKnyk35C9FeFnrTRttKJjlJqSGClHdZC2PR6aI9ee+l652JGTSYC\r\n"
"SwaTVUMiTR0G4RwL2yAtDxRe8+f/p/omNn24EivmtzVMQzAh7NiEofcd2fL/y72P\r\n"
"gCax92ECgYEA6ESWQ55h9FNUGOX/TEHHYxxugwpHJlTgZfFJ745FveGmzpaSzODb\r\n"
"4Q5PQc9Ioxy9eX+YzM0xzpBjHZ/mgm1ENG4Yl9m7goWFRwu3Zl0S/PIsC7VAYfWr\r\n"
"/MfDNI0Y1Uly+wW2AgDwHTdAfjWPh2iDWgseG7sd/pVc6RMJcLYGjukCgYEA3IKu\r\n"
"S4vbejwIJ+hsTCtKsR2UnyvkOB8vKZ5vVJNGQxVTHoiFXHwWyfTPTe9mj6TqLEZH\r\n"
"4nZKIzgmsNRXKoElDnz2y9np3pM23AJUQV4G5q3QhMQcY6FO/FoPUEqO0pwwQiC2\r\n"
"fpNheTsVBmC+nech2YEaaoQ8bXHAOvUD+brjhXMCgYAP9ma9Tu08dV2aOHRLMVoa\r\n"
"naGar+Ij6EFjwClspUJ1wkRMflyoZ+u0k98ujqhXTWpYJ0TBDnkV0SZ+qraU0B2X\r\n"
"3Nkj1nrkhXibYVrBVjQv3hTY2SQLl26yeKgZvHiwb9PPHJ1dleLqnxl3kwbCL5SX\r\n"
"Y5w2G638CRfRjNVhQaFBwQKBgHmyYZDuAdXnFbU4r7Ql3FX9dk2WQqC6jSPR/a1W\r\n"
"jltthG8Ad2GAVm9k/ZgMfLTgFiETNI8GK4pebfP/bI/XsGTbkLUWcdzVsFwhqPBe\r\n"
"fT6IROFQ/j36A4aACZ2NWF9htbx5I16d5hirA8J+WBT7P5IzjymkC1l3gtjG6kfD\r\n"
"3deDAoGBAI2jH3NenBVfYIcqfgMbaIu4UxUNLVbXSt+PtAnWvWDIIcx7LdBLabMl\r\n"
"SagxUVGkTmUaylaR9udAVYon0YdW57TRBZqWQAgSyo7RmQpQYzFKKX/4iUxr7igj\r\n"
"mzvHG03BPJWSUzByovFY6dbn/QbYvd5w763vG02vu5kp09rOdZZB\r\n"
"-----END RSA PRIVATE KEY-----\r\n";

//Dummy private key assigned to allocate buffer
const char eccprivatekey[] =
"-----BEGIN EC PRIVATE KEY-----\r\n"
"MHcCAQEEIDkoXdx0gErvQDm8TyDoqWJibRSo0GWNCjWR6oMjKUhRoAoGCCqGSM49\r\n"
"AwEHoUQDQgAEU7b1qd5vN0sCxEn8On2uoFEkD9c9APP1rOT/JPinjkASxzpbpxgp\r\n"
"bjBkpNh8Or8AmGboQjRUnFgGUA+AB6OoQg==\r\n"
"-----END EC PRIVATE KEY-----\r\n";

static int callbackCounter;
static char msgText[1024];
static char propText[1024];
static bool g_continueRunning;
#define MESSAGE_COUNT CONFIG_MESSAGE_COUNT
#define DOWORK_LOOP_NUM     3

typedef struct EVENT_INSTANCE_TAG
{
    IOTHUB_MESSAGE_HANDLE messageHandle;
    size_t messageTrackingId;  // For tracking the messages within the user callback.
} EVENT_INSTANCE;

static IOTHUBMESSAGE_DISPOSITION_RESULT ReceiveMessageCallback(IOTHUB_MESSAGE_HANDLE message, void* userContextCallback)
{
    int* counter = (int*)userContextCallback;
    const char* buffer;
    size_t size;
    MAP_HANDLE mapProperties;
    const char* messageId;
    const char* correlationId;

    // Message properties
    if ((messageId = IoTHubMessage_GetMessageId(message)) == NULL)
    {
        messageId = "<null>";
    }

    if ((correlationId = IoTHubMessage_GetCorrelationId(message)) == NULL)
    {
        correlationId = "<null>";
    }

    // Message content
    if (IoTHubMessage_GetByteArray(message, (const unsigned char**)&buffer, &size) != IOTHUB_MESSAGE_OK)
    {
        (void)printf("unable to retrieve the message data\r\n");
    }
    else
    {
        (void)printf("Received Message [%d]\r\n Message ID: %s\r\n Correlation ID: %s\r\n Data: <<<%.*s>>> & Size=%d\r\n", *counter, messageId, correlationId, (int)size, buffer, (int)size);
        // If we receive the work 'quit' then we stop running
        if (size == (strlen("quit") * sizeof(char)) && memcmp(buffer, "quit", size) == 0)
        {
            g_continueRunning = false;
        }
    }

    // Retrieve properties from the message
    mapProperties = IoTHubMessage_Properties(message);
    if (mapProperties != NULL)
    {
        const char*const* keys;
        const char*const* values;
        size_t propertyCount = 0;
        if (Map_GetInternals(mapProperties, &keys, &values, &propertyCount) == MAP_OK)
        {
            if (propertyCount > 0)
            {
                size_t index;

                printf(" Message Properties:\r\n");
                for (index = 0; index < propertyCount; index++)
                {
                    (void)printf("\tKey: %s Value: %s\r\n", keys[index], values[index]);
                }
                (void)printf("\r\n");
            }
        }
    }

    /* Some device specific action code goes here... */
    (*counter)++;
    return IOTHUBMESSAGE_ACCEPTED;
}

static void SendConfirmationCallback(IOTHUB_CLIENT_CONFIRMATION_RESULT result, void* userContextCallback)
{
    EVENT_INSTANCE* eventInstance = (EVENT_INSTANCE*)userContextCallback;
    size_t id = eventInstance->messageTrackingId;

    if (result == IOTHUB_CLIENT_CONFIRMATION_OK) {
        (void)printf("Confirmation[%d] received for message tracking id = %d with result = %s\r\n", callbackCounter, (int)id, MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONFIRMATION_RESULT, result));
        /* Some device specific action code goes here... */
        callbackCounter++;
    }
    IoTHubMessage_Destroy(eventInstance->messageHandle);
}

void connection_status_callback(IOTHUB_CLIENT_CONNECTION_STATUS result, IOTHUB_CLIENT_CONNECTION_STATUS_REASON reason, void* userContextCallback)
{
    (void)printf("\n\nConnection Status result:%s, Connection Status reason: %s\n\n", MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONNECTION_STATUS, result),
                 MU_ENUM_TO_STRING(IOTHUB_CLIENT_CONNECTION_STATUS_REASON, reason));
}

extern void read_certificate_from_optiga(char * cert_pem, uint16_t * length);
extern void read_trust_anchor_from_optiga(uint16_t oid, char * cert_pem, uint16_t * cert_pem_length);
extern uint32_t pal_os_timer_get_time_in_milliseconds(void);

void iothub_client_sample_mqtt_run(void)
{
    IOTHUB_CLIENT_LL_HANDLE iotHubClientHandle;

    EVENT_INSTANCE message;

    g_continueRunning = true;
    srand((unsigned int)time(NULL));
    double avgWindSpeed = 10.0;
    double minTemperature = 20.0;
    double minHumidity = 60.0;

    callbackCounter = 0;
    int receiveContext = 0;

    if (platform_init() != 0)
    {
        (void)printf("Failed to initialize the platform.\r\n");
    }
    else
    {
        if ((iotHubClientHandle = IoTHubClient_LL_CreateFromConnectionString(connectionString, MQTT_Protocol)) == NULL)
        {
            (void)printf("ERROR: iotHubClientHandle is NULL!\r\n");
        }
        else
        {
            bool traceOn = true;
            //IoTHubClient_LL_SetOption(iotHubClientHandle, OPTION_LOG_TRACE, &traceOn);

            IoTHubClient_LL_SetConnectionStatusCallback(iotHubClientHandle, connection_status_callback, NULL);
            // Setting the Trusted Certificate.  This is only necessary on system with without
            // built in certificate stores.
#ifdef SET_TRUSTED_CERT_IN_SAMPLES
            #ifdef LOAD_TA_FROM_OPTIGA
			/*Trust Anchor is required to validate server
			below api requires server root certificate to be pre-loaded in data object (optiga trust anchor)
			provide oid where server CA is loaded Ex:0xE0E8 */
			read_trust_anchor_from_optiga(CONFIG_OPTIGA_TRUST_M_TRUSTANCHOR_SLOT, trust_anchor_pem, &trust_anchor_pem_length);
			char const * const certificates = trust_anchor_pem;
			#endif

			IoTHubDeviceClient_LL_SetOption(iotHubClientHandle, OPTION_TRUSTED_CERT, certificates);
#endif // SET_TRUSTED_CERT_IN_SAMPLES
			
            // Set the X509 certificates in the SDK
			read_certificate_from_optiga(device_certificate_pem, &device_certificate_pem_length);
			if((CONFIG_OPTIGA_TRUST_M_PRIVKEY_SLOT == 0xE0FC) || (CONFIG_OPTIGA_TRUST_M_PRIVKEY_SLOT == 0xE0FD))
			{
				if(0x41 == CONFIG_RSA_KEY_SIZE)
				{
					privatekey = rsa1024privatekey;
				}
				else
				{
					privatekey = rsa2048privatekey;
				}
			}
			else
			{
				privatekey = eccprivatekey;
			}
				
			if (
                (IoTHubDeviceClient_LL_SetOption(iotHubClientHandle, OPTION_X509_CERT, device_certificate_pem) != IOTHUB_CLIENT_OK) ||
                (IoTHubDeviceClient_LL_SetOption(iotHubClientHandle, OPTION_X509_PRIVATE_KEY, privatekey) != IOTHUB_CLIENT_OK)
                )
            {
                printf("failure to set options for x509, aborting\r\n");
                return;
            }
			
            /* Setting Message call back, so we can receive Commands. */
            if (IoTHubClient_LL_SetMessageCallback(iotHubClientHandle, ReceiveMessageCallback, &receiveContext) != IOTHUB_CLIENT_OK)
            {
                (void)printf("ERROR: IoTHubClient_LL_SetMessageCallback..........FAILED!\r\n");
            }
            else
            {
                (void)printf("IoTHubClient_LL_SetMessageCallback...successful.\r\n");

                /* Now that we are ready to receive commands, let's send some messages */
                int iterator = 0;
                double temperature = 0;
                double humidity = 0;
                time_t sent_time = 0;
                time_t current_time = 0;
                do
                {
                    //(void)printf("iterator: [%d], callbackCounter: [%d]. \r\n", iterator, callbackCounter);
                    time(&current_time);
                    if ((MESSAGE_COUNT == 0 || iterator < MESSAGE_COUNT)
                        && iterator <= callbackCounter
                        && (difftime(current_time, sent_time) > ((CONFIG_MESSAGE_INTERVAL_TIME) / 1000)))
                    {
                        temperature = minTemperature + (rand() % 10);
                        humidity = minHumidity +  (rand() % 20);
                        sprintf_s(msgText, sizeof(msgText), "{\"deviceId\":\"myFirstDevice-san\",\"windSpeed\":%.2f,\"temperature\":%.2f,\"humidity\":%.2f}", avgWindSpeed + (rand() % 4 + 2), temperature, humidity);
                        if ((message.messageHandle = IoTHubMessage_CreateFromByteArray((const unsigned char*)msgText, strlen(msgText))) == NULL)
                        {
                            (void)printf("ERROR: iotHubMessageHandle is NULL!\r\n");
                        }
                        else
                        {
                            message.messageTrackingId = iterator;
                            MAP_HANDLE propMap = IoTHubMessage_Properties(message.messageHandle);
                            (void)sprintf_s(propText, sizeof(propText), temperature > 28 ? "true" : "false");
                            if (Map_AddOrUpdate(propMap, "temperatureAlert", propText) != MAP_OK)
                            {
                                (void)printf("ERROR: Map_AddOrUpdate Failed!\r\n");
                            }

                            if (IoTHubClient_LL_SendEventAsync(iotHubClientHandle, message.messageHandle, SendConfirmationCallback, &message) != IOTHUB_CLIENT_OK)
                            {
                                (void)printf("ERROR: IoTHubClient_LL_SendEventAsync..........FAILED!\r\n");
                            }
                            else
                            {
                                time(&sent_time);
                                (void)printf("IoTHubClient_LL_SendEventAsync accepted message [%d] for transmission to IoT Hub.\r\n", (int)iterator);
                            }
                        }
                        iterator++;
                    }
                    IoTHubClient_LL_DoWork(iotHubClientHandle);
                    ThreadAPI_Sleep(10);

                    if (MESSAGE_COUNT != 0 && callbackCounter >= MESSAGE_COUNT)
                    {
                        printf("exit\n");
                        break;
                    }
                } while (g_continueRunning);

                (void)printf("iothub_client_sample_mqtt has gotten quit message, call DoWork %d more time to complete final sending...\r\n", DOWORK_LOOP_NUM);
                size_t index = 0;
                for (index = 0; index < DOWORK_LOOP_NUM; index++)
                {
                    IoTHubClient_LL_DoWork(iotHubClientHandle);
                    ThreadAPI_Sleep(1);
                }
            }
            IoTHubClient_LL_Destroy(iotHubClientHandle);
        }
        platform_deinit();
    }
}

int main(void)
{
    iothub_client_sample_mqtt_run();
    return 0;
}
