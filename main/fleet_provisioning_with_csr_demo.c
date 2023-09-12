/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * Demo for showing use of the Fleet Provisioning library to use the Fleet
 * Provisioning feature of AWS IoT Core for provisioning devices with
 * credentials. This demo shows how a device can be provisioned with AWS IoT
 * Core using the Certificate Signing Request workflow of the Fleet
 * Provisioning feature.
 *
 * The Fleet Provisioning library provides macros and helper functions for
 * assembling MQTT topics strings, and for determining whether an incoming MQTT
 * message is related to the Fleet Provisioning API of AWS IoT Core. The Fleet
 * Provisioning library does not depend on any particular MQTT library,
 * therefore the functionality for MQTT operations is placed in another file
 * (mqtt_operations.c). This demo uses the coreMQTT library. If needed,
 * mqtt_operations.c can be modified to replace coreMQTT with another MQTT
 * library. This demo requires using the AWS IoT Core broker as Fleet
 * Provisioning is an AWS IoT Core feature.
 *
 * This demo provisions a device certificate using the provisioning by claim
 * workflow with a Certificate Signing Request (CSR). The demo connects to AWS
 * IoT Core using provided claim credentials (whose certificate needs to be
 * registered with IoT Core before running this demo), subscribes to the
 * CreateCertificateFromCsr topics, and obtains a certificate. It then
 * subscribes to the RegisterThing topics and activates the certificate and
 * obtains a Thing using the provisioning template. Finally, it reconnects to
 * AWS IoT Core using the new credentials.
 */

/* Standard includes. */
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

/* POSIX includes. */
#include <unistd.h>
#include <errno.h>

/* Demo config. */
#include "demo_config.h"

/* corePKCS11 includes. */
#include "core_pkcs11.h"
#include "core_pkcs11_config.h"

/* AWS IoT Fleet Provisioning Library. */
#include "fleet_provisioning.h"

/* Demo includes. */
#include "mqtt_operations.h"
#include "pkcs11_operations.h"
#include "fleet_provisioning_serializer.h"

#include "nvs.h"
#include "nvs_flash.h"

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "core_json.h"
#include "uart_echo.h"

/**
 * @brief Status values of the Fleet Provisioning response.
 */
typedef enum
{
    ResponseNotReceived,
    ResponseAccepted,
    ResponseRejected
} ResponseStatus_t;


/*-----------------------------------------------------------*/

/**
 * @brief Status reported from the MQTT publish callback.
 */
static ResponseStatus_t responseStatus;

/**
 * @brief Buffer to hold the provisioned AWS IoT Thing name.
 */
static char thingName[ MAX_THING_NAME_LENGTH ];

/**
 * @brief Length of the AWS IoT Thing name.
 */
static size_t thingNameLength;

/**
 * @brief Buffer to hold responses received from the AWS IoT Fleet Provisioning
 * APIs. When the MQTT publish callback receives an expected Fleet Provisioning
 * accepted payload, it copies it into this buffer.
 */
static uint8_t payloadBuffer[ NETWORK_BUFFER_SIZE ];

/**
 * @brief Length of the payload stored in #payloadBuffer. This is set by the
 * MQTT publish callback when it copies a received payload into #payloadBuffer.
 */
static size_t payloadLength;

/*-----------------------------------------------------------*/

/**
 * @brief Callback to receive the incoming publish messages from the MQTT
 * broker. Sets responseStatus if an expected CreateCertificateFromCsr or
 * RegisterThing response is received, and copies the response into
 * responseBuffer if the response is an accepted one.
 *
 * @param[in] pPublishInfo Pointer to publish info of the incoming publish.
 * @param[in] packetIdentifier Packet identifier of the incoming publish.
 */
static void provisioningPublishCallback( MQTTPublishInfo_t * pPublishInfo,
                                         uint16_t packetIdentifier );

/**
 * @brief Run the MQTT process loop to get a response.
 */
static bool waitForResponse( void );

/**
 * @brief Subscribe to the CreateCertificateFromCsr accepted and rejected topics.
 */
static bool subscribeToCsrResponseTopics( void );

/**
 * @brief Unsubscribe from the CreateCertificateFromCsr accepted and rejected topics.
 */
static bool unsubscribeFromCsrResponseTopics( void );

/**
 * @brief Subscribe to the RegisterThing accepted and rejected topics.
 */
static bool subscribeToRegisterThingResponseTopics( void );

/**
 * @brief Unsubscribe from the RegisterThing accepted and rejected topics.
 */
static bool unsubscribeFromRegisterThingResponseTopics( void );

/*-----------------------------------------------------------*/

uint32_t Clock_GetTimeMs( void )
{
    /* esp_timer_get_time is in microseconds, converting to milliseconds */
    int64_t timeMs = esp_timer_get_time() / 1000;

    /* Libraries need only the lower 32 bits of the time in milliseconds, since
     * this function is used only for calculating the time difference.
     * Also, the possible overflows of this time value are handled by the
     * libraries. */
    return ( uint32_t ) timeMs;
}

/*-----------------------------------------------------------*/

void Clock_SleepMs( uint32_t sleepTimeMs )
{
    vTaskDelay( sleepTimeMs/portTICK_PERIOD_MS );
}

/*-----------------------------------------------------------*/

static void provisioningPublishCallback( MQTTPublishInfo_t * pPublishInfo,
                                         uint16_t packetIdentifier )
{
    FleetProvisioningStatus_t status;
    FleetProvisioningTopic_t api;
    const char * cborDump;

    /* Silence compiler warnings about unused variables. */
    ( void ) packetIdentifier;

    status = FleetProvisioning_MatchTopic( pPublishInfo->pTopicName,
                                           pPublishInfo->topicNameLength, &api );

    if( status != FleetProvisioningSuccess )
    {
        LogWarn( ( "Unexpected publish message received. Topic: %.*s.",
                   ( int ) pPublishInfo->topicNameLength,
                   ( const char * ) pPublishInfo->pTopicName ) );
    }
    else
    {
        if( api == FleetProvCborCreateCertFromCsrAccepted )
        {
            LogInfo( ( "Received accepted response from Fleet Provisioning CreateCertificateFromCsr API." ) );

            cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
            LogDebug( ( "Payload: %s", cborDump ) );
            free( ( void * ) cborDump );

            responseStatus = ResponseAccepted;

            /* Copy the payload from the MQTT library's buffer to #payloadBuffer. */
            ( void ) memcpy( ( void * ) payloadBuffer,
                             ( const void * ) pPublishInfo->pPayload,
                             ( size_t ) pPublishInfo->payloadLength );

            payloadLength = pPublishInfo->payloadLength;
        }
        else if( api == FleetProvCborCreateCertFromCsrRejected )
        {
            LogError( ( "Received rejected response from Fleet Provisioning CreateCertificateFromCsr API." ) );

            cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
            LogError( ( "Payload: %s", cborDump ) );
            free( ( void * ) cborDump );

            responseStatus = ResponseRejected;
        }
        else if( api == FleetProvCborRegisterThingAccepted )
        {
            LogInfo( ( "Received accepted response from Fleet Provisioning RegisterThing API." ) );

            cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
            LogDebug( ( "Payload: %s", cborDump ) );
            free( ( void * ) cborDump );

            responseStatus = ResponseAccepted;

            /* Copy the payload from the MQTT library's buffer to #payloadBuffer. */
            ( void ) memcpy( ( void * ) payloadBuffer,
                             ( const void * ) pPublishInfo->pPayload,
                             ( size_t ) pPublishInfo->payloadLength );

            payloadLength = pPublishInfo->payloadLength;
        }
        else if( api == FleetProvCborRegisterThingRejected )
        {
            LogError( ( "Received rejected response from Fleet Provisioning RegisterThing API." ) );

            cborDump = getStringFromCbor( ( const uint8_t * ) pPublishInfo->pPayload, pPublishInfo->payloadLength );
            LogError( ( "Payload: %s", cborDump ) );
            free( ( void * ) cborDump );

            responseStatus = ResponseRejected;
        }
        else
        {
            LogError( ( "Received message on unexpected Fleet Provisioning topic. Topic: %.*s.",
                        ( int ) pPublishInfo->topicNameLength,
                        ( const char * ) pPublishInfo->pTopicName ) );
        }
    }
}

/*-----------------------------------------------------------*/

static bool waitForResponse( void )
{
    bool status = false;

    responseStatus = ResponseNotReceived;

    /* responseStatus is updated from the MQTT publish callback. */
    ( void ) ProcessLoopWithTimeout();

    if( responseStatus == ResponseNotReceived )
    {
        LogError( ( "Timed out waiting for response." ) );
    }

    if( responseStatus == ResponseAccepted )
    {
        status = true;
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool subscribeToCsrResponseTopics( void )
{
    bool status;

    status = SubscribeToTopic( FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC,
                               FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH );

    if( status == false )
    {
        LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                    FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH,
                    FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC ) );
    }

    if( status == true )
    {
        status = SubscribeToTopic( FP_CBOR_CREATE_CERT_REJECTED_TOPIC,
                                   FP_CBOR_CREATE_CERT_REJECTED_LENGTH );

        if( status == false )
        {
            LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                        FP_CBOR_CREATE_CERT_REJECTED_LENGTH,
                        FP_CBOR_CREATE_CERT_REJECTED_TOPIC ) );
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool unsubscribeFromCsrResponseTopics( void )
{
    bool status;

    status = UnsubscribeFromTopic( FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC,
                                   FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH );

    if( status == false )
    {
        LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                    FP_CBOR_CREATE_CERT_ACCEPTED_LENGTH,
                    FP_CBOR_CREATE_CERT_ACCEPTED_TOPIC ) );
    }

    if( status == true )
    {
        status = UnsubscribeFromTopic( FP_CBOR_CREATE_CERT_REJECTED_TOPIC,
                                       FP_CBOR_CREATE_CERT_REJECTED_LENGTH );

        if( status == false )
        {
            LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                        FP_CBOR_CREATE_CERT_REJECTED_LENGTH,
                        FP_CBOR_CREATE_CERT_REJECTED_TOPIC ) );
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool subscribeToRegisterThingResponseTopics( void )
{
    bool status;

    status = SubscribeToTopic( FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                               FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ) );

    if( status == false )
    {
        LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                    FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                    FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
    }

    if( status == true )
    {
        status = SubscribeToTopic( FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                                   FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ) );

        if( status == false )
        {
            LogError( ( "Failed to subscribe to fleet provisioning topic: %.*s.",
                        FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                        FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

static bool unsubscribeFromRegisterThingResponseTopics( void )
{
    bool status;

    status = UnsubscribeFromTopic( FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                                   FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ) );

    if( status == false )
    {
        LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                    FP_CBOR_REGISTER_ACCEPTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                    FP_CBOR_REGISTER_ACCEPTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
    }

    if( status == true )
    {
        status = UnsubscribeFromTopic( FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                                       FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ) );

        if( status == false )
        {
            LogError( ( "Failed to unsubscribe from fleet provisioning topic: %.*s.",
                        FP_CBOR_REGISTER_REJECTED_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                        FP_CBOR_REGISTER_REJECTED_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
        }
    }

    return status;
}
/*-----------------------------------------------------------*/

/* This example uses a single application task, which shows that how to use
 * the Fleet Provisioning library to generate and validate AWS IoT Fleet
 * Provisioning MQTT topics, and use the coreMQTT library to communicate with
 * the AWS IoT Fleet Provisioning APIs. */
int aws_iot_demo_main( int argc,
          char ** argv )
{
    bool status = false;
    /* Buffer for holding the CSR. */
    char csr[ CSR_BUFFER_LENGTH ] = { 0 };
    size_t csrLength = 0;
    /* Buffer for holding received certificate until it is saved. */
    char certificate[ CERT_BUFFER_LENGTH ];
    size_t certificateLength;
    /* Buffer for holding the certificate ID. */
    char certificateId[ CERT_ID_BUFFER_LENGTH ];
    size_t certificateIdLength;
    /* Buffer for holding the certificate ownership token. */
    char ownershipToken[ OWNERSHIP_TOKEN_BUFFER_LENGTH ];
    size_t ownershipTokenLength;
    bool connectionEstablished = false;
    CK_SESSION_HANDLE p11Session;
    int demoRunCount = 0;
    CK_RV pkcs11ret = CKR_OK;

    /* Silence compiler warnings about unused variables. */
    ( void ) argc;
    ( void ) argv;

    /* Check for credentials in the system from custom partition */
    ESP_ERROR_CHECK(nvs_flash_init_partition("aws_nvs"));

    /* Open partition */
    nvs_handle handle;
    ESP_ERROR_CHECK(nvs_open_from_partition("aws_nvs", "certs", NVS_READWRITE, &handle));

    AWS_Certs certs;
    size_t certs_size = sizeof(AWS_Certs);
    esp_err_t ret = nvs_get_blob(handle, "certs", (void *)&certs, &certs_size);
    LogInfo( ( "Actual aws certs size=%d returned from NVS=%d", ( int ) sizeof(AWS_Certs), ( int ) certs_size ) );

    bool certificate_found = false;
    switch(ret)
    {
        case ESP_ERR_NOT_FOUND:
        case ESP_ERR_NVS_NOT_FOUND:
            ESP_LOGE("app", "key not set");
            certificate_found = false;
            break;
        case ESP_OK:
            ESP_LOGI("app", "certificates found!");
            LogInfo( ( "NVS payloadBuffer: %.*s\nsize: %d", ( int ) certs.payloadLength, certs.payloadBuffer, ( int ) certs.payloadLength ) );
            LogInfo( ( "NVS certificate: %.*s\nsize: %d", ( int ) certs.certificateLength, certs.certificate, ( int ) certs.certificateLength ) );
            LogInfo( ( "NVS certificate with Id: %.*s\nsize: %d", ( int ) certs.certificateIdLength, certs.certificateId, ( int ) certs.certificateIdLength ) );
            LogInfo( ( "NVS ownershipToken: %.*s\nsize: %d", ( int ) certs.ownershipTokenLength, certs.ownershipToken, ( int ) certs.ownershipTokenLength ) );
            LogInfo( ( "NVS thingName: %.*s\nsize: %d", ( int ) certs.thingNameLength, certs.thingName, ( int ) certs.thingNameLength ) );
            certificate_found = true;
            break;
        default:
            certificate_found = false;
            ESP_LOGE("app", "Error (%s) opening NVS handle\n", esp_err_to_name(ret));
    }

    do
    {
        /* Initialize the PKCS #11 module */
        pkcs11ret = xInitializePkcs11Session( &p11Session );

        if(!certificate_found)
        {
            /* Initialize the buffer lengths to their max lengths. */
            certificateLength = CERT_BUFFER_LENGTH;
            certificateIdLength = CERT_ID_BUFFER_LENGTH;
            ownershipTokenLength = OWNERSHIP_TOKEN_BUFFER_LENGTH;

            if( pkcs11ret != CKR_OK )
            {
                LogError( ( "Failed to initialize PKCS #11." ) );
                status = false;
            }
            else
            {
                /* Insert the claim credentials into the PKCS #11 module */
                status = loadClaimCredentials( p11Session,
                                            CLAIM_CERT_PATH,
                                            pkcs11configLABEL_CLAIM_CERTIFICATE,
                                            CLAIM_PRIVATE_KEY_PATH,
                                            pkcs11configLABEL_CLAIM_PRIVATE_KEY );

                if( status == false )
                {
                    LogError( ( "Failed to provision PKCS #11 with claim credentials." ) );
                }
            }

            /**** Connect to AWS IoT Core with provisioning claim credentials *****/

            /* We first use the claim credentials to connect to the broker. These
            * credentials should allow use of the RegisterThing API and one of the
            * CreateCertificatefromCsr or CreateKeysAndCertificate.
            * In this demo we use CreateCertificatefromCsr. */

            if( status == true )
            {
                /* Attempts to connect to the AWS IoT MQTT broker. If the
                * connection fails, retries after a timeout. Timeout value will
                * exponentially increase until maximum attempts are reached. */
                LogInfo( ( "Establishing MQTT session with claim certificate..." ) );
                status = EstablishMqttSession( provisioningPublishCallback,
                                            p11Session,
                                            pkcs11configLABEL_CLAIM_CERTIFICATE,
                                            pkcs11configLABEL_CLAIM_PRIVATE_KEY );

                if( status == false )
                {
                    LogError( ( "Failed to establish MQTT session." ) );
                }
                else
                {
                    LogInfo( ( "Established connection with claim credentials." ) );
                    connectionEstablished = true;
                }
            }

            /**** Call the CreateCertificateFromCsr API ***************************/

            /* We use the CreateCertificatefromCsr API to obtain a client certificate
            * for a key on the device by means of sending a certificate signing
            * request (CSR). */
            if( status == true )
            {
                /* Subscribe to the CreateCertificateFromCsr accepted and rejected
                * topics. In this demo we use CBOR encoding for the payloads,
                * so we use the CBOR variants of the topics. */
                status = subscribeToCsrResponseTopics();
            }

            if( status == true )
            {
                /* Create a new key and CSR. */
                status = generateKeyAndCsr( p11Session,
                                            pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS,
                                            pkcs11configLABEL_DEVICE_PUBLIC_KEY_FOR_TLS,
                                            csr,
                                            CSR_BUFFER_LENGTH,
                                            &csrLength );
            }

            if( status == true )
            {
                /* Create the request payload containing the CSR to publish to the
                * CreateCertificateFromCsr APIs. */
                status = generateCsrRequest( payloadBuffer,
                                            NETWORK_BUFFER_SIZE,
                                            csr,
                                            csrLength,
                                            &payloadLength );
            }

            if( status == true )
            {
                /* Publish the CSR to the CreateCertificatefromCsr API. */
                PublishToTopic( FP_CBOR_CREATE_CERT_PUBLISH_TOPIC,
                                FP_CBOR_CREATE_CERT_PUBLISH_LENGTH,
                                ( char * ) payloadBuffer,
                                payloadLength );

                if( status == false )
                {
                    LogError( ( "Failed to publish to fleet provisioning topic: %.*s.",
                                FP_CBOR_CREATE_CERT_PUBLISH_LENGTH,
                                FP_CBOR_CREATE_CERT_PUBLISH_TOPIC ) );
                }
            }

            if( status == true )
            {
                /* Get the response to the CreateCertificatefromCsr request. */
                status = waitForResponse();
            }

            if( status == true )
            {
                /* From the response, extract the certificate, certificate ID, and
                * certificate ownership token. */
                status = parseCsrResponse( payloadBuffer,
                                        payloadLength,
                                        certificate,
                                        &certificateLength,
                                        certificateId,
                                        &certificateIdLength,
                                        ownershipToken,
                                        &ownershipTokenLength );

                if( status == true )
                {
                    LogInfo( ( "Received payloadBuffer: %.*s\nsize: %d", ( int ) payloadLength, payloadBuffer, ( int ) payloadLength ) );
                    LogInfo( ( "Received certificate: %.*s\nsize: %d", ( int ) certificateLength, certificate, ( int ) certificateLength ) );
                    LogInfo( ( "Received certificate with Id: %.*s\nsize: %d", ( int ) certificateIdLength, certificateId, ( int ) certificateIdLength ) );
                    LogInfo( ( "Received ownershipToken: %.*s\nsize: %d", ( int ) ownershipTokenLength, ownershipToken, ( int ) ownershipTokenLength ) );
                    
                }
            }

            if( status == true )
            {
                /* Save the certificate into PKCS #11. */
                status = loadCertificate( p11Session,
                                        certificate,
                                        pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                        certificateLength );
            }

            if( status == true )
            {
                /* Unsubscribe from the CreateCertificateFromCsr topics. */
                status = unsubscribeFromCsrResponseTopics();
            }

            /**** Call the RegisterThing API **************************************/

            /* We then use the RegisterThing API to activate the received certificate,
            * provision AWS IoT resources according to the provisioning template, and
            * receive device configuration. */
            if( status == true )
            {
                /* Create the request payload to publish to the RegisterThing API. */
                status = generateRegisterThingRequest( payloadBuffer,
                                                    NETWORK_BUFFER_SIZE,
                                                    ownershipToken,
                                                    ownershipTokenLength,
                                                    DEVICE_SERIAL_NUMBER,
                                                    DEVICE_SERIAL_NUMBER_LENGTH,
                                                    &payloadLength );
            }

            if( status == true )
            {
                /* Subscribe to the RegisterThing response topics. */
                status = subscribeToRegisterThingResponseTopics();
            }

            if( status == true )
            {
                /* Publish the RegisterThing request. */
                PublishToTopic( FP_CBOR_REGISTER_PUBLISH_TOPIC( PROVISIONING_TEMPLATE_NAME ),
                                FP_CBOR_REGISTER_PUBLISH_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                                ( char * ) payloadBuffer,
                                payloadLength );

                if( status == false )
                {
                    LogError( ( "Failed to publish to fleet provisioning topic: %.*s.",
                                FP_CBOR_REGISTER_PUBLISH_LENGTH( PROVISIONING_TEMPLATE_NAME_LENGTH ),
                                FP_CBOR_REGISTER_PUBLISH_TOPIC( PROVISIONING_TEMPLATE_NAME ) ) );
                }
            }

            if( status == true )
            {
                /* Get the response to the RegisterThing request. */
                status = waitForResponse();
            }

            if( status == true )
            {
                /* Extract the Thing name from the response. */
                thingNameLength = MAX_THING_NAME_LENGTH;
                status = parseRegisterThingResponse( payloadBuffer,
                                                    payloadLength,
                                                    thingName,
                                                    &thingNameLength );

                if( status == true )
                {
                    LogInfo( ( "Received AWS IoT Thing name: %.*s", ( int ) thingNameLength, thingName ) );
                }
            }

            if( status == true )
            {
                /* Unsubscribe from the RegisterThing topics. */
                unsubscribeFromRegisterThingResponseTopics();
            }

            /**** Disconnect from AWS IoT Core ************************************/

            /* As we have completed the provisioning workflow, we disconnect from
            * the connection using the provisioning claim credentials. We will
            * establish a new MQTT connection with the newly provisioned
            * credentials. */
            if( connectionEstablished == true )
            {
                DisconnectMqttSession();
                connectionEstablished = false;

                /* Once all the process is completed, we are going to save the data used for storage */
                memcpy(certs.payloadBuffer, payloadBuffer, payloadLength);
                certs.payloadLength = payloadLength;
                
                memcpy(certs.certificate, certificate, certificateLength);
                certs.certificateLength = certificateLength;
                
                memcpy(certs.certificateId, certificateId, certificateIdLength);
                certs.certificateIdLength = certificateIdLength;
                
                memcpy(certs.ownershipToken, ownershipToken, ownershipTokenLength);
                certs.ownershipTokenLength = ownershipTokenLength;

                memcpy(certs.thingName, thingName, thingNameLength);
                certs.thingNameLength = thingNameLength;

                ESP_ERROR_CHECK(nvs_set_blob(handle, "certs", (void *)&certs, sizeof(AWS_Certs)));
                ESP_ERROR_CHECK(nvs_commit(handle));
            }
        }
        else
        {
            /* Check if PKCS #11 is already initialized */
            if( pkcs11ret != CKR_OK )
            {
                LogError( ( "Failed to initialize PKCS #11." ) );
                status = false;
            }
            else {
                status = true;
                LogInfo( ( "Establishing MQTT session with STORED certificate..." ) );
                /* Data was already stored, so let's load it into the used variables of the system */
                memcpy(payloadBuffer, certs.payloadBuffer, certs.payloadLength);
                payloadLength = certs.payloadLength;
                
                memcpy(certificate, certs.certificate, certs.certificateLength);
                certificateLength = certs.certificateLength;
                
                memcpy(certificateId, certs.certificateId, certs.certificateIdLength);
                certificateIdLength = certs.certificateIdLength;
                
                memcpy(ownershipToken, certs.ownershipToken, certs.ownershipTokenLength);
                certs.ownershipTokenLength = certs.ownershipTokenLength;

                memcpy(thingName, certs.thingName, certs.thingNameLength);
                thingNameLength = certs.thingNameLength;
            }
        }

        /**** Connect to AWS IoT Core with provisioned certificate ************/

        if( status == true )
        {
            LogInfo( ( "Establishing MQTT session with provisioned certificate..." ) );
            status = EstablishMqttSession( handleIncomingPublish,
                                           p11Session,
                                           pkcs11configLABEL_DEVICE_CERTIFICATE_FOR_TLS,
                                           pkcs11configLABEL_DEVICE_PRIVATE_KEY_FOR_TLS );

            if( status != true )
            {
                LogError( ( "Failed to establish MQTT session with provisioned "
                            "credentials. Verify on your AWS account that the "
                            "new certificate is active and has an attached IoT "
                            "Policy that allows the \"iot:Connect\" action." ) );
            }
            else
            {
                LogInfo( ( "Sucessfully established connection with provisioned credentials." ) );
                connectionEstablished = true;
            }
        }

        if(connectionEstablished == true)
        {
            status = subscribeToLightTopic(thingName, thingNameLength);
            if(status == EXIT_SUCCESS)
            {
                LogInfo( ( "Sucessfully Subscription." ) );
            }
            // else
            // {
            //     LogInfo( ( "Failed Subscription." ) );
            // }
            for(;;)
            {
                // if(PublishToTopic(thingName, thingNameLength, "hello-2", 8))
                // {
                //     LogInfo(("message sent"));
                // }
                // else
                // {
                //     LogInfo(("not working correctly"));
                // }
                waitForResponse();
                char buff[3];
                size_t l = 3;
                bool listened = uart_listen(buff, l);
            }
        }

        /**** Finish **********************************************************/

        if( connectionEstablished == true )
        {
            /* Close the connection. */
            DisconnectMqttSession();
            connectionEstablished = false;
        }

        pkcs11CloseSession( p11Session );

        /**** Retry in case of failure ****************************************/

        /* Increment the demo run count. */
        demoRunCount++;

        if( status == true )
        {
            LogInfo( ( "Demo iteration %d is successful.", demoRunCount ) );
        }
        /* Attempt to retry a failed iteration of demo for up to #FLEET_PROV_MAX_DEMO_LOOP_COUNT times. */
        else if( demoRunCount < FLEET_PROV_MAX_DEMO_LOOP_COUNT )
        {
            LogWarn( ( "Demo iteration %d failed. Retrying...", demoRunCount ) );
            sleep( DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_SECONDS );
        }
        /* Failed all #FLEET_PROV_MAX_DEMO_LOOP_COUNT demo iterations. */
        else
        {
            LogError( ( "All %d demo iterations failed.", FLEET_PROV_MAX_DEMO_LOOP_COUNT ) );
            break;
        }
    } while( status != true );

    /* Log demo success. */
    if( status == true )
    {
        LogInfo( ( "Demo completed successfully." ) );
    }

    nvs_close(handle);

    return ( status == true ) ? EXIT_SUCCESS : EXIT_FAILURE;
}
/*-----------------------------------------------------------*/
