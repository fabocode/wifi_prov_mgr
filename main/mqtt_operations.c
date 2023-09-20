/*
 * AWS IoT Device SDK for Embedded C 202211.00
 * Copyright (C) 2020 Amazon.com, Inc. or its affiliates.  All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 * the Software, and to permit persons to whom the Software is furnished to do so,
 * subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 * COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**
 * @file mqtt_operations.c
 *
 * @brief This file provides wrapper functions for MQTT operations on a mutually
 * authenticated TLS connection.
 *
 * A mutually authenticated TLS connection is used to connect to the AWS IoT
 * MQTT message broker in this example. Define ROOT_CA_CERT_PATH,
 * CLIENT_CERT_PATH, and CLIENT_PRIVATE_KEY_PATH in demo_config.h to achieve
 * mutual authentication.
 */

/* Standard includes. */
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

/* POSIX includes. */
#include <unistd.h>

/* Config include. */
#include "demo_config.h"

/* Interface include. */
#include "mqtt_operations.h"

/* MbedTLS transport include. */
#include "mbedtls_pkcs11_posix.h"

/*Include backoff algorithm header for retry logic.*/
#include "backoff_algorithm.h"

/* Clock for timer. */
#include "clock.h"

/*Include coreJSON library. */
#include "core_json.h"

#include "uart_echo.h"

/* SHADOW API header. */
#include "shadow.h"

/* JSON API header. */
#include "core_json.h"

/* Clock for timer. */
#include "clock.h"

/**
 * These configurations are required. Throw compilation error if the below
 * configs are not defined.
 */
#ifndef AWS_IOT_ENDPOINT
    #error "Please define AWS IoT MQTT broker endpoint(AWS_IOT_ENDPOINT) in demo_config.h."
#endif
#ifndef ROOT_CA_CERT_PATH
    #error "Please define path to Root CA certificate of the MQTT broker(ROOT_CA_CERT_PATH) in demo_config.h."
#endif
#ifndef CLIENT_IDENTIFIER
    #error "Please define a unique CLIENT_IDENTIFIER."
#endif

/**
 * Provide default values for undefined configuration settings.
 */
#ifndef AWS_MQTT_PORT
    #define AWS_MQTT_PORT    ( 8883 )
#endif

/**
 * @brief ALPN protocol name for AWS IoT MQTT.
 *
 * This will be used if the democonfigMQTT_BROKER_PORT is configured as 443 for AWS IoT MQTT broker.
 * Please see more details about the ALPN protocol for AWS IoT MQTT endpoint
 * in the link below.
 * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
 */
#define ALPN_PROTOCOL_NAME           "x-amzn-mqtt-ca"

/**
 * @brief Length of the AWS IoT endpoint.
 */
#define AWS_IOT_ENDPOINT_LENGTH                  ( ( uint16_t ) ( sizeof( AWS_IOT_ENDPOINT ) - 1 ) )

/**
 * @brief Length of the client identifier.
 */
#define CLIENT_IDENTIFIER_LENGTH                 ( ( uint16_t ) ( sizeof( CLIENT_IDENTIFIER ) - 1 ) )

/**
 * @brief The maximum number of retries for connecting to server.
 */
#define CONNECTION_RETRY_MAX_ATTEMPTS            ( 5U )

/**
 * @brief The maximum back-off delay (in milliseconds) for retrying connection to server.
 */
#define CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS    ( 5000U )

/**
 * @brief The base back-off delay (in milliseconds) to use for connection retry attempts.
 */
#define CONNECTION_RETRY_BACKOFF_BASE_MS         ( 500U )

/**
 * @brief Timeout for receiving CONNACK packet in milliseconds.
 */
#define CONNACK_RECV_TIMEOUT_MS                  ( 1000U )

/**
 * @brief Maximum number of outgoing publishes maintained in the application
 * until an ack is received from the broker.
 */
#define MAX_OUTGOING_PUBLISHES                   ( 5U )

/**
 * @brief Invalid packet identifier for the MQTT packets. Zero is always an
 * invalid packet identifier as per MQTT 3.1.1 spec.
 */
#define MQTT_PACKET_ID_INVALID                   ( ( uint16_t ) 0U )

/**
 * @brief Timeout for MQTT_ProcessLoop function in milliseconds.
 */
#define MQTT_PROCESS_LOOP_TIMEOUT_MS             ( 1000U )

/**
 * @brief The maximum time interval in seconds which is allowed to elapse
 *  between two Control Packets.
 *
 *  It is the responsibility of the client to ensure that the interval between
 *  control packets being sent does not exceed the this keep-alive value. In the
 *  absence of sending any other control packets, the client MUST send a
 *  PINGREQ packet.
 */
#define MQTT_KEEP_ALIVE_INTERVAL_SECONDS         ( 60U )

/**
 * @brief Timeout in milliseconds for transport send and receive.
 */
#define TRANSPORT_SEND_RECV_TIMEOUT_MS           ( 3000U )

/**
 * @brief The MQTT metrics string expected by AWS IoT MQTT Broker.
 */
#define METRICS_STRING                           "?SDK=" OS_NAME "&Version=" OS_VERSION "&Platform=" HARDWARE_PLATFORM_NAME "&MQTTLib=" MQTT_LIB

/**
 * @brief The length of the MQTT metrics string.
 */
#define METRICS_STRING_LENGTH                    ( ( uint16_t ) ( sizeof( METRICS_STRING ) - 1 ) )

/**
 * @brief The length of the outgoing publish records array used by the coreMQTT
 * library to track QoS > 0 packet ACKS for outgoing publishes.
 */
#define OUTGOING_PUBLISH_RECORD_LEN              ( 10U )

/**
 * @brief The length of the incoming publish records array used by the coreMQTT
 * library to track QoS > 0 packet ACKS for incoming publishes.
 */
#define INCOMING_PUBLISH_RECORD_LEN              ( 10U )
/*-----------------------------------------------------------*/

/**
 * @brief Format string representing a Shadow document with a "desired" state.
 *
 * The real json document will look like this:
 * {
 *   "state": {
 *     "desired": {
 *       "powerOn": 1
 *     }
 *   },
 *   "clientToken": "021909"
 * }
 *
 * Note the client token, which is optional for all Shadow updates. The client
 * token must be unique at any given time, but may be reused once the update is
 * completed. For this demo, a timestamp is used for a client token.
 */
#define SHADOW_DESIRED_JSON     \
    "{"                         \
    "\"state\":{"               \
    "\"desired\":{"             \
    "\"powerOn\":%01d"          \
    "}"                         \
    "},"                        \
    "\"clientToken\":\"%06lu\"" \
    "}"

/**
 * @brief The expected size of #SHADOW_DESIRED_JSON.
 *
 * Because all the format specifiers in #SHADOW_DESIRED_JSON include a length,
 * its full actual size is known by pre-calculation, here's the formula why
 * the length need to minus 3:
 * 1. The length of "%01d" is 4.
 * 2. The length of %06lu is 5.
 * 3. The actual length we will use in case 1. is 1 ( for the state of powerOn ).
 * 4. The actual length we will use in case 2. is 6 ( for the clientToken length ).
 * 5. Thus the additional size 3 = 4 + 5 - 1 - 6 + 1 (termination character).
 *
 * In your own application, you could calculate the size of the json doc in this way.
 */
#define SHADOW_DESIRED_JSON_LENGTH    ( sizeof( SHADOW_DESIRED_JSON ) - 3 )

/**
 * @brief Format string representing a Shadow document with a "reported" state.
 *
 * The real json document will look like this:
 * {
 *   "state": {
 *     "reported": {
 *       "powerOn": 1
 *     }
 *   },
 *   "clientToken": "021909"
 * }
 *
 * Note the client token, which is required for all Shadow updates. The client
 * token must be unique at any given time, but may be reused once the update is
 * completed. For this demo, a timestamp is used for a client token.
 */
#define SHADOW_REPORTED_JSON    \
    "{"                         \
    "\"state\":{"               \
    "\"reported\":{"            \
    "\"powerOn\":%01d"          \
    "}"                         \
    "},"                        \
    "\"clientToken\":\"%06lu\"" \
    "}"

/**
 * @brief The expected size of #SHADOW_REPORTED_JSON.
 *
 * Because all the format specifiers in #SHADOW_REPORTED_JSON include a length,
 * its full size is known at compile-time by pre-calculation. Users could refer to
 * the way how to calculate the actual length in #SHADOW_DESIRED_JSON_LENGTH.
 */
#define SHADOW_REPORTED_JSON_LENGTH    ( sizeof( SHADOW_REPORTED_JSON ) - 3 )

/**
 * @brief The maximum number of times to run the loop in this demo.
 *
 * @note The demo loop is attempted to re-run only if it fails in an iteration.
 * Once the demo loop succeeds in an iteration, the demo exits successfully.
 */
#ifndef SHADOW_MAX_DEMO_LOOP_COUNT
    #define SHADOW_MAX_DEMO_LOOP_COUNT    ( 3 )
#endif

/**
 * @brief Time in seconds to wait between retries of the demo loop if
 * demo loop fails.
 */
#define DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_S           ( 5 )

/**
 * @brief JSON key for response code that indicates the type of error in
 * the error document received on topic `/delete/rejected`.
 */
#define SHADOW_DELETE_REJECTED_ERROR_CODE_KEY           "code"

/**
 * @brief Length of #SHADOW_DELETE_REJECTED_ERROR_CODE_KEY
 */
#define SHADOW_DELETE_REJECTED_ERROR_CODE_KEY_LENGTH    ( ( uint16_t ) ( sizeof( SHADOW_DELETE_REJECTED_ERROR_CODE_KEY ) - 1 ) )

/*-----------------------------------------------------------*/

/**
 * @brief The simulated device current power on state.
 */
static uint32_t currentPowerOnState = 0;

/**
 * @brief The flag to indicate the device current power on state changed.
 */
static bool stateChanged = false;

/**
 * @brief When we send an update to the device shadow, and if we care about
 * the response from cloud (accepted/rejected), remember the clientToken and
 * use it to match with the response.
 */
static uint32_t clientToken = 0U;

/**
 * @brief Indicator that an error occurred during the MQTT event callback. If an
 * error occurred during the MQTT event callback, then the demo has failed.
 */
static bool eventCallbackError = false;

/**
 * @brief Status of the response of Shadow delete operation from AWS IoT
 * message broker.
 */
static bool deleteResponseReceived = false;

/**
 * @brief Status of the Shadow delete operation.
 *
 * The Shadow delete status will be updated by the incoming publishes on the
 * MQTT topics for delete acknowledgement from AWS IoT message broker
 * (accepted/rejected). Shadow document is considered to be deleted if an
 * incoming publish is received on `/delete/accepted` topic or an incoming
 * publish is received on `/delete/rejected` topic with error code 404. Code 404
 * indicates that the Shadow document does not exist for the Thing yet.
 */
static bool shadowDeleted = false;


/**
 * @brief Structure to keep the MQTT publish packets until an ack is received
 * for QoS1 publishes.
 */
typedef struct PublishPackets
{
    /**
     * @brief Packet identifier of the publish packet.
     */
    uint16_t packetId;

    /**
     * @brief Publish info of the publish packet.
     */
    MQTTPublishInfo_t pubInfo;
} PublishPackets_t;

/* Each compilation unit must define the NetworkContext struct. */
struct NetworkContext
{
    MbedtlsPkcs11Context_t * pParams;
};
/*-----------------------------------------------------------*/

/**
 * @brief Packet Identifier updated when an ACK packet is received.
 *
 * It is used to match an expected ACK for a transmitted packet.
 */
static uint16_t globalAckPacketIdentifier = 0U;

/**
 * @brief Packet Identifier generated when Subscribe request was sent to the broker.
 *
 * It is used to match received Subscribe ACK to the transmitted subscribe
 * request.
 */
static uint16_t globalSubscribePacketIdentifier = 0U;

/**
 * @brief Packet Identifier generated when Unsubscribe request was sent to the broker.
 *
 * It is used to match received Unsubscribe ACK to the transmitted unsubscribe
 * request.
 */
static uint16_t globalUnsubscribePacketIdentifier = 0U;

/**
 * @brief Array to keep the outgoing publish messages.
 *
 * These stored outgoing publish messages are kept until a successful ack
 * is received.
 */
static PublishPackets_t outgoingPublishPackets[ MAX_OUTGOING_PUBLISHES ] = { 0 };

/**
 * @brief Array to keep subscription topics.
 * Used to re-subscribe to topics that failed initial subscription attempts.
 */
static MQTTSubscribeInfo_t pGlobalSubscriptionList[ 1 ];

/**
 * @brief The network buffer must remain valid for the lifetime of the MQTT context.
 */
static uint8_t buffer[ NETWORK_BUFFER_SIZE ];

/**
 * @brief Status of latest Subscribe ACK;
 * it is updated every time the callback function processes a Subscribe ACK
 * and accounts for subscription to a single topic.
 */
static MQTTSubAckStatus_t globalSubAckStatus = MQTTSubAckFailure;

/**
 * @brief The MQTT context used for MQTT operation.
 */
static MQTTContext_t mqttContext = { 0 };

/**
 * @brief The network context used for MbedTLS operation.
 */
static NetworkContext_t networkContext = { 0 };

/**
 * @brief The parameters for MbedTLS operation.
 */
static MbedtlsPkcs11Context_t tlsContext = { 0 };

/**
 * @brief The flag to indicate that the mqtt session is established.
 */
static bool mqttSessionEstablished = false;

/**
 * @brief Callback registered when calling EstablishMqttSession to get incoming
 * publish messages.
 */
static MQTTPublishCallback_t appPublishCallback = NULL;

/**
 * @brief Array to track the outgoing publish records for outgoing publishes
 * with QoS > 0.
 *
 * This is passed into #MQTT_InitStatefulQoS to allow for QoS > 0.
 *
 */
static MQTTPubAckInfo_t pOutgoingPublishRecords[ OUTGOING_PUBLISH_RECORD_LEN ];

/**
 * @brief Array to track the incoming publish records for incoming publishes
 * with QoS > 0.
 *
 * This is passed into #MQTT_InitStatefulQoS to allow for QoS > 0.
 *
 */
static MQTTPubAckInfo_t pIncomingPublishRecords[ INCOMING_PUBLISH_RECORD_LEN ];

/**
 * @brief Buffer to hold the provisioned AWS IoT Thing name.
 */
static char subscribedTopicName[ MAX_THING_NAME_LENGTH ];

/**
 * @brief Length of the AWS IoT Thing name.
 */
static size_t subscribedTopicNameLength;
/*-----------------------------------------------------------*/

/**
 * @brief Process payload from /update/delta topic.
 *
 * This handler examines the version number and the powerOn state. If powerOn
 * state has changed, it sets a flag for the main function to take further actions.
 *
 * @param[in] pPublishInfo Deserialized publish info pointer for the incoming
 * packet.
 */
static void updateDeltaHandler( MQTTPublishInfo_t * pPublishInfo );

/**
 * @brief Process payload from /update/accepted topic.
 *
 * This handler examines the accepted message that carries the same clientToken
 * as sent before.
 *
 * @param[in] pPublishInfo Deserialized publish info pointer for the incoming
 * packet.
 */
static void updateAcceptedHandler( MQTTPublishInfo_t * pPublishInfo );

/**
 * @brief Process payload from `/delete/rejected` topic.
 *
 * This handler examines the rejected message to look for the reject reason code.
 * If the reject reason code is `404`, an attempt was made to delete a shadow
 * document which was not present yet. This is considered to be success for this
 * demo application.
 *
 * @param[in] pPublishInfo Deserialized publish info pointer for the incoming
 * packet.
 */
static void deleteRejectedHandler( MQTTPublishInfo_t * pPublishInfo );

/*-----------------------------------------------------------*/

int device_shadow_demo(void)
{
    int returnStatus = EXIT_SUCCESS;
    int demoRunCount = 0;


    /* A buffer containing the update document. It has static duration to prevent
     * it from being placed on the call stack. */
    static char updateDocument[ SHADOW_REPORTED_JSON_LENGTH + 1 ] = { 0 };

    do
    {
        // returnStatus = EstablishMqttSession( eventCallback );
        LogInfo(("Running DeviceShadow example"));
        if( returnStatus == EXIT_FAILURE )
        {
            /* Log error to indicate connection failure. */
            LogError( ( "Failed to connect to MQTT broker." ) );
        }
        else
        {
            LogInfo(("Running DeviceShadow example watching"));
            /* Reset the shadow delete status flags. */
            deleteResponseReceived = false;
            shadowDeleted = false;

            /* First of all, try to delete any Shadow document in the cloud.
            * Try to subscribe to `/delete/accepted` and `/delete/rejected` topics. */
            returnStatus = SubscribeToTopic( SHADOW_TOPIC_STR_DELETE_ACC( THING_NAME, SHADOW_NAME ),
                                            SHADOW_TOPIC_LEN_DELETE_ACC( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );

            if( returnStatus == EXIT_SUCCESS )
            {
                /* Try to subscribe to `/delete/rejected` topic. */
                returnStatus = SubscribeToTopic( SHADOW_TOPIC_STR_DELETE_REJ( THING_NAME, SHADOW_NAME ),
                                                SHADOW_TOPIC_LEN_DELETE_REJ( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                /* Publish to Shadow `delete` topic to attempt to delete the
                * Shadow document if exists. */
                returnStatus = PublishToTopic( SHADOW_TOPIC_STR_DELETE( THING_NAME, SHADOW_NAME ),
                                            SHADOW_TOPIC_LEN_DELETE( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ),
                                            updateDocument,
                                            0U );
            }

            /* Unsubscribe from the `/delete/accepted` and 'delete/rejected` topics.*/
            if( returnStatus == EXIT_SUCCESS )
            {
                returnStatus = UnsubscribeFromTopic( SHADOW_TOPIC_STR_DELETE_ACC( THING_NAME, SHADOW_NAME ),
                                                    SHADOW_TOPIC_LEN_DELETE_ACC( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                returnStatus = UnsubscribeFromTopic( SHADOW_TOPIC_STR_DELETE_REJ( THING_NAME, SHADOW_NAME ),
                                                    SHADOW_TOPIC_LEN_DELETE_REJ( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            /* Check if an incoming publish on `/delete/accepted` or `/delete/rejected`
            * topics. If a response is not received, mark the demo execution as a failure.*/
            if( ( returnStatus == EXIT_SUCCESS ) && ( deleteResponseReceived != true ) )
            {
                LogError( ( "Failed to receive a response for Shadow delete." ) );
                returnStatus = EXIT_FAILURE;
            }

            /* Check if Shadow document delete was successful. A delete can be
            * successful in cases listed below.
            *  1. If an incoming publish is received on `/delete/accepted` topic.
            *  2. If an incoming publish is received on `/delete/rejected` topic
            *     with an error code 404. This indicates that a delete was
            *     attempted when a Shadow document is not available for the
            *     Thing. */
            if( returnStatus == EXIT_SUCCESS )
            {
                if( shadowDeleted == false )
                {
                    LogError( ( "Shadow delete operation failed." ) );
                    returnStatus = EXIT_FAILURE;
                }
            }

            /* Successfully connect to MQTT broker, the next step is
            * to subscribe shadow topics. */
            if( returnStatus == EXIT_SUCCESS )
            {
                returnStatus = SubscribeToTopic( SHADOW_TOPIC_STR_UPDATE_DELTA( THING_NAME, SHADOW_NAME ),
                                                SHADOW_TOPIC_LEN_UPDATE_DELTA( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                returnStatus = SubscribeToTopic( SHADOW_TOPIC_STR_UPDATE_ACC( THING_NAME, SHADOW_NAME ),
                                                SHADOW_TOPIC_LEN_UPDATE_ACC( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                returnStatus = SubscribeToTopic( SHADOW_TOPIC_STR_UPDATE_REJ( THING_NAME, SHADOW_NAME ),
                                                SHADOW_TOPIC_LEN_UPDATE_REJ( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            /* This demo uses a constant #THING_NAME and #SHADOW_NAME known at compile time therefore
            * we can use macros to assemble shadow topic strings.
            * If the thing name or shadow name is only known at run time, then we could use the API
            * #Shadow_AssembleTopicString to assemble shadow topic strings, here is the example for /update/delta:
            *
            * For /update/delta:
            *
            * #define SHADOW_TOPIC_MAX_LENGTH  (256U)
            *
            * ShadowStatus_t shadowStatus = SHADOW_SUCCESS;
            * char topicBuffer[ SHADOW_TOPIC_MAX_LENGTH ] = { 0 };
            * uint16_t bufferSize = SHADOW_TOPIC_MAX_LENGTH;
            * uint16_t outLength = 0;
            * const char thingName[] = { "TestThingName" };
            * uint16_t thingNameLength  = ( sizeof( thingName ) - 1U );
            * const char shadowName[] = { "TestShadowName" };
            * uint16_t shadowNameLength  = ( sizeof( shadowName ) - 1U );
            *
            * shadowStatus = Shadow_AssembleTopicString( ShadowTopicStringTypeUpdateDelta,
            *                                            thingName,
            *                                            thingNameLength,
            *                                            shadowName,
            *                                            shadowNameLength,
            *                                            & ( topicBuffer[ 0 ] ),
            *                                            bufferSize,
            *                                            & outLength );
            */

            /* Then we publish a desired state to the /update topic. Since we've deleted
            * the device shadow at the beginning of the demo, this will cause a delta message
            * to be published, which we have subscribed to.
            * In many real applications, the desired state is not published by
            * the device itself. But for the purpose of making this demo self-contained,
            * we publish one here so that we can receive a delta message later.
            */
            if( returnStatus == EXIT_SUCCESS )
            {
                /* desired power on state . */
                LogInfo( ( "Send desired power state with 1." ) );

                ( void ) memset( updateDocument,
                                0x00,
                                sizeof( updateDocument ) );

                /* Keep the client token in global variable used to compare if
                * the same token in /update/accepted. */
                clientToken = ( Clock_GetTimeMs() % 1000000 );

                snprintf( updateDocument,
                        SHADOW_DESIRED_JSON_LENGTH + 1,
                        SHADOW_DESIRED_JSON,
                        ( int ) 1,
                        ( long unsigned ) clientToken );

                returnStatus = PublishToTopic( SHADOW_TOPIC_STR_UPDATE( THING_NAME, SHADOW_NAME ),
                                            SHADOW_TOPIC_LEN_UPDATE( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ),
                                            updateDocument,
                                            ( SHADOW_DESIRED_JSON_LENGTH + 1 ) );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                /* Note that PublishToTopic already called MQTT_ProcessLoop,
                * therefore responses may have been received and the eventCallback
                * may have been called, which may have changed the stateChanged flag.
                * Check if the state change flag has been modified or not. If it's modified,
                * then we publish reported state to update topic.
                */
                if( stateChanged == true )
                {
                    /* Report the latest power state back to device shadow. */
                    LogInfo( ( "Report to the state change: %"PRIu32"", currentPowerOnState ) );
                    ( void ) memset( updateDocument,
                                    0x00,
                                    sizeof( updateDocument ) );

                    /* Keep the client token in global variable used to compare if
                    * the same token in /update/accepted. */
                    clientToken = ( Clock_GetTimeMs() % 1000000 );

                    snprintf( updateDocument,
                            SHADOW_REPORTED_JSON_LENGTH + 1,
                            SHADOW_REPORTED_JSON,
                            ( int ) currentPowerOnState,
                            ( long unsigned ) clientToken );

                    returnStatus = PublishToTopic( SHADOW_TOPIC_STR_UPDATE( THING_NAME, SHADOW_NAME ),
                                                SHADOW_TOPIC_LEN_UPDATE( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ),
                                                updateDocument,
                                                ( SHADOW_REPORTED_JSON_LENGTH + 1 ) );
                }
                else
                {
                    LogInfo( ( "No change from /update/delta, unsubscribe all shadow topics and disconnect from MQTT.\r\n" ) );
                }
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                LogInfo( ( "Start to unsubscribe shadow topics and disconnect from MQTT. \r\n" ) );
                returnStatus = UnsubscribeFromTopic( SHADOW_TOPIC_STR_UPDATE_DELTA( THING_NAME, SHADOW_NAME ),
                                                    SHADOW_TOPIC_LEN_UPDATE_DELTA( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                returnStatus = UnsubscribeFromTopic( SHADOW_TOPIC_STR_UPDATE_ACC( THING_NAME, SHADOW_NAME ),
                                                    SHADOW_TOPIC_LEN_UPDATE_ACC( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            if( returnStatus == EXIT_SUCCESS )
            {
                returnStatus = UnsubscribeFromTopic( SHADOW_TOPIC_STR_UPDATE_REJ( THING_NAME, SHADOW_NAME ),
                                                    SHADOW_TOPIC_LEN_UPDATE_REJ( THING_NAME_LENGTH, SHADOW_NAME_LENGTH ) );
            }

            /* The MQTT session is always disconnected, even there were prior failures. */
            returnStatus = DisconnectMqttSession();
        }

        /* This demo performs only Device Shadow operations. If matching the Shadow
        * topic fails or there are failures in parsing the received JSON document,
        * then this demo was not successful. */
        if( eventCallbackError == true )
        {
            returnStatus = EXIT_FAILURE;
        }
        
        /* Increment the demo run count. */
        demoRunCount++;
        if( returnStatus == EXIT_SUCCESS )
        {
            LogInfo( ( "Demo iteration %d is successful.", demoRunCount ) );
        }
        /* Attempt to retry a failed iteration of demo for up to #SHADOW_MAX_DEMO_LOOP_COUNT times. */
        else if( demoRunCount < SHADOW_MAX_DEMO_LOOP_COUNT )
        {
            LogWarn( ( "Demo iteration %d failed. Retrying...", demoRunCount ) );
            sleep( DELAY_BETWEEN_DEMO_RETRY_ITERATIONS_S );
        }
        /* Failed all #SHADOW_MAX_DEMO_LOOP_COUNT demo iterations. */
        else
        {
            LogError( ( "All %d demo iterations failed.", SHADOW_MAX_DEMO_LOOP_COUNT ) );
            break;
        }
    } while( returnStatus != EXIT_SUCCESS );

    return returnStatus;
}

static void deleteRejectedHandler( MQTTPublishInfo_t * pPublishInfo )
{
    JSONStatus_t result = JSONSuccess;
    char * pOutValue = NULL;
    uint32_t outValueLength = 0U;
    long errorCode = 0L;

    assert( pPublishInfo != NULL );
    assert( pPublishInfo->pPayload != NULL );

    LogInfo( ( "/delete/rejected json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* The payload will look similar to this:
     * {
     *    "code": error-code,
     *    "message": "error-message",
     *    "timestamp": timestamp,
     *    "clientToken": "token"
     * }
     */

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate( ( const char * ) pPublishInfo->pPayload,
                            pPublishInfo->payloadLength );

    if( result == JSONSuccess )
    {
        /* Then we start to get the version value by JSON keyword "version". */
        result = JSON_Search( ( char * ) pPublishInfo->pPayload,
                              pPublishInfo->payloadLength,
                              SHADOW_DELETE_REJECTED_ERROR_CODE_KEY,
                              SHADOW_DELETE_REJECTED_ERROR_CODE_KEY_LENGTH,
                              &pOutValue,
                              ( size_t * ) &outValueLength );
    }
    else
    {
        LogError( ( "The json document is invalid!!" ) );
    }

    if( result == JSONSuccess )
    {
        LogInfo( ( "Error code is: %.*s.",
                   (int) outValueLength,
                   pOutValue ) );

        /* Convert the extracted value to an unsigned integer value. */
        errorCode = strtoul( pOutValue, NULL, 10 );
    }
    else
    {
        LogError( ( "No error code in json document!!" ) );
    }

    LogInfo( ( "Error code:%ld.", errorCode ) );

    /* Mark Shadow delete operation as a success if error code is 404. */
    if( errorCode == 404UL )
    {
        shadowDeleted = true;
    }
}

/*-----------------------------------------------------------*/

static void updateDeltaHandler( MQTTPublishInfo_t * pPublishInfo )
{
    static uint32_t currentVersion = 0; /* Remember the latestVersion # we've ever received */
    uint32_t version = 0U;
    uint32_t newState = 0U;
    char * outValue = NULL;
    uint32_t outValueLength = 0U;
    JSONStatus_t result = JSONSuccess;

    assert( pPublishInfo != NULL );
    assert( pPublishInfo->pPayload != NULL );

    LogInfo( ( "/update/delta json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* The payload will look similar to this:
     * {
     *      "version": 12,
     *      "timestamp": 1595437367,
     *      "state": {
     *          "powerOn": 1
     *      },
     *      "metadata": {
     *          "powerOn": {
     *          "timestamp": 1595437367
     *          }
     *      },
     *      "clientToken": "388062"
     *  }
     */

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate( ( const char * ) pPublishInfo->pPayload,
                            pPublishInfo->payloadLength );

    if( result == JSONSuccess )
    {
        /* Then we start to get the version value by JSON keyword "version". */
        result = JSON_Search( ( char * ) pPublishInfo->pPayload,
                              pPublishInfo->payloadLength,
                              "version",
                              sizeof( "version" ) - 1,
                              &outValue,
                              ( size_t * ) &outValueLength );
    }
    else
    {
        LogError( ( "The json document is invalid!!" ) );
        eventCallbackError = true;
    }

    if( result == JSONSuccess )
    {
        LogInfo( ( "version: %.*s",
                   (int) outValueLength,
                   outValue ) );

        /* Convert the extracted value to an unsigned integer value. */
        version = ( uint32_t ) strtoul( outValue, NULL, 10 );
    }
    else
    {
        LogError( ( "No version in json document!!" ) );
        eventCallbackError = true;
    }

    LogInfo( ( "version:%"PRIu32", currentVersion:%"PRIu32" \r\n", version, currentVersion ) );

    /* When the version is much newer than the on we retained, that means the powerOn
     * state is valid for us. */
    if( version > currentVersion )
    {
        /* Set to received version as the current version. */
        currentVersion = version;

        /* Get powerOn state from json documents. */
        result = JSON_Search( ( char * ) pPublishInfo->pPayload,
                              pPublishInfo->payloadLength,
                              "state.powerOn",
                              sizeof( "state.powerOn" ) - 1,
                              &outValue,
                              ( size_t * ) &outValueLength );
    }
    else
    {
        /* In this demo, we discard the incoming message
         * if the version number is not newer than the latest
         * that we've received before. Your application may use a
         * different approach.
         */
        LogWarn( ( "The received version is smaller than current one!!" ) );
    }

    if( result == JSONSuccess )
    {
        /* Convert the powerOn state value to an unsigned integer value. */
        newState = ( uint32_t ) strtoul( outValue, NULL, 10 );

        LogInfo( ( "The new power on state newState:%"PRIu32", currentPowerOnState:%"PRIu32" \r\n",
                   newState, currentPowerOnState ) );

        if( newState != currentPowerOnState )
        {
            /* The received powerOn state is different from the one we retained before, so we switch them
             * and set the flag. */
            currentPowerOnState = newState;

            /* State change will be handled in main(), where we will publish a "reported"
             * state to the device shadow. We do not do it here because we are inside of
             * a callback from the MQTT library, so that we don't re-enter
             * the MQTT library. */
            stateChanged = true;
        }
    }
    else
    {
        LogError( ( "No powerOn in json document!!" ) );
        eventCallbackError = true;
    }
}

/*-----------------------------------------------------------*/

static void updateAcceptedHandler( MQTTPublishInfo_t * pPublishInfo )
{
    char * outValue = NULL;
    uint32_t outValueLength = 0U;
    uint32_t receivedToken = 0U;
    JSONStatus_t result = JSONSuccess;

    assert( pPublishInfo != NULL );
    assert( pPublishInfo->pPayload != NULL );

    LogInfo( ( "/update/accepted json payload:%s.", ( const char * ) pPublishInfo->pPayload ) );

    /* Handle the reported state with state change in /update/accepted topic.
     * Thus we will retrieve the client token from the json document to see if
     * it's the same one we sent with reported state on the /update topic.
     * The payload will look similar to this:
     *  {
     *      "state": {
     *          "reported": {
     *          "powerOn": 1
     *          }
     *      },
     *      "metadata": {
     *          "reported": {
     *          "powerOn": {
     *              "timestamp": 1596573647
     *          }
     *          }
     *      },
     *      "version": 14698,
     *      "timestamp": 1596573647,
     *      "clientToken": "022485"
     *  }
     */

    /* Make sure the payload is a valid json document. */
    result = JSON_Validate( ( const char * ) pPublishInfo->pPayload,
                            pPublishInfo->payloadLength );

    if( result == JSONSuccess )
    {
        /* Get clientToken from json documents. */
        result = JSON_Search( ( char * ) pPublishInfo->pPayload,
                              pPublishInfo->payloadLength,
                              "clientToken",
                              sizeof( "clientToken" ) - 1,
                              &outValue,
                              ( size_t * ) &outValueLength );
    }
    else
    {
        LogError( ( "Invalid json documents !!" ) );
        eventCallbackError = true;
    }

    if( result == JSONSuccess )
    {
        LogInfo( ( "clientToken: %.*s", (int) outValueLength,
                   outValue ) );

        /* Convert the code to an unsigned integer value. */
        receivedToken = ( uint32_t ) strtoul( outValue, NULL, 10 );

        LogInfo( ( "receivedToken:%"PRIu32", clientToken:%"PRIu32" \r\n", receivedToken, clientToken ) );

        /* If the clientToken in this update/accepted message matches the one we
         * published before, it means the device shadow has accepted our latest
         * reported state. We are done. */
        if( receivedToken == clientToken )
        {
            LogInfo( ( "Received response from the device shadow. Previously published "
                       "update with clientToken=%"PRIu32" has been accepted. ", clientToken ) );
        }
        else
        {
            LogWarn( ( "The received clientToken=%"PRIu32" is not identical with the one=%"PRIu32" we sent "
                       , receivedToken, clientToken ) );
        }
    }
    else
    {
        LogError( ( "No clientToken in json document!!" ) );
        eventCallbackError = true;
    }
}


static aws_mqtt_state_t aws_action = INVALID;

void set_aws_action(aws_mqtt_state_t action)
{
    aws_action = action;
}

/**
 * @brief The random number generator to use for exponential backoff with
 * jitter retry logic.
 *
 * @return The generated random number.
 */
static uint32_t generateRandomNumber( void );

/**
 * @brief Connect to the MQTT broker with reconnection retries.
 *
 * If connection fails, retry is attempted after a timeout. Timeout value
 * exponentially increases until maximum timeout value is reached or the number
 * of attempts are exhausted.
 *
 * @param[out] pNetworkContext The created network context.
 * @param[in] p11Session The PKCS #11 session to use.
 * @param[in] pClientCertLabel The client certificate PKCS #11 label to use.
 * @param[in] pPrivateKeyLabel The private key PKCS #11 label for the client certificate.
 *
 * @return false on failure; true on successful connection.
 */
static bool connectToBrokerWithBackoffRetries( NetworkContext_t * pNetworkContext,
                                               CK_SESSION_HANDLE p11Session,
                                               char * pClientCertLabel,
                                               char * pPrivateKeyLabel );

/**
 * @brief Get the free index in the #outgoingPublishPackets array at which an
 * outgoing publish can be stored.
 *
 * @param[out] pIndex The index at which an outgoing publish can be stored.
 *
 * @return false if no more publishes can be stored;
 * true if an index to store the next outgoing publish is obtained.
 */
static bool getNextFreeIndexForOutgoingPublishes( uint8_t * pIndex );

/**
 * @brief Clean up the outgoing publish at given index from the
 * #outgoingPublishPackets array.
 *
 * @param[in] index The index at which a publish message has to be cleaned up.
 */
static void cleanupOutgoingPublishAt( uint8_t index );

/**
 * @brief Clean up all the outgoing publishes in the #outgoingPublishPackets array.
 */
static void cleanupOutgoingPublishes( void );

/**
 * @brief Clean up the publish packet with the given packet id in the
 * #outgoingPublishPackets array.
 *
 * @param[in] packetId Packet id of the packet to be clean.
 */
static void cleanupOutgoingPublishWithPacketID( uint16_t packetId );

/**
 * @brief Callback registered with the MQTT library.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] pPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] pDeserializedInfo Deserialized information from the incoming packet.
 */
static void mqttCallback( MQTTContext_t * pMqttContext,
                          MQTTPacketInfo_t * pPacketInfo,
                          MQTTDeserializedInfo_t * pDeserializedInfo );

/**
 * @brief Resend the publishes if a session is re-established with the broker.
 *
 * This function handles the resending of the QoS1 publish packets, which are
 * maintained locally.
 *
 * @param[in] pMqttContext The MQTT context pointer.
 *
 * @return true if all the unacknowledged QoS1 publishes are re-sent successfully;
 * false otherwise.
 */
static bool handlePublishResend( MQTTContext_t * pMqttContext );

/**
 * @brief Wait for an expected ACK packet to be received.
 *
 * This function handles waiting for an expected ACK packet by calling
 * #MQTT_ProcessLoop and waiting for #mqttCallback to set the global ACK
 * packet identifier to the expected ACK packet identifier.
 *
 * @param[in] pMqttContext MQTT context pointer.
 * @param[in] usPacketIdentifier Packet identifier for expected ACK packet.
 * @param[in] ulTimeout Maximum duration to wait for expected ACK packet.
 *
 * @return true if the expected ACK packet was received, false otherwise.
 */
static bool waitForPacketAck( MQTTContext_t * pMqttContext,
                              uint16_t usPacketIdentifier,
                              uint32_t ulTimeout );
/*-----------------------------------------------------------*/

static uint32_t generateRandomNumber()
{
    return( ( uint32_t ) rand() );
}
/*-----------------------------------------------------------*/

static bool connectToBrokerWithBackoffRetries( NetworkContext_t * pNetworkContext,
                                               CK_SESSION_HANDLE p11Session,
                                               char * pClientCertLabel,
                                               char * pPrivateKeyLabel )
{
    bool returnStatus = false;
    BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
    MbedtlsPkcs11Status_t tlsStatus = MBEDTLS_PKCS11_SUCCESS;
    BackoffAlgorithmContext_t reconnectParams;
    MbedtlsPkcs11Credentials_t tlsCredentials = { 0 };
    uint16_t nextRetryBackOff = 0U;

    /* Set the pParams member of the network context with desired transport. */
    pNetworkContext->pParams = &tlsContext;

    /* Initialize credentials for establishing TLS session. */
    tlsCredentials.pRootCaPath = ROOT_CA_CERT_PATH;
    tlsCredentials.pClientCertLabel = pClientCertLabel;
    tlsCredentials.pPrivateKeyLabel = pPrivateKeyLabel;
    tlsCredentials.p11Session = p11Session;

    /* AWS IoT requires devices to send the Server Name Indication (SNI)
     * extension to the Transport Layer Security (TLS) protocol and provide
     * the complete endpoint address in the host_name field. Details about
     * SNI for AWS IoT can be found in the link below.
     * https://docs.aws.amazon.com/iot/latest/developerguide/transport-security.html
     */
    tlsCredentials.disableSni = false;

    if( AWS_MQTT_PORT == 443 )
    {
        static const char * alpnProtoArray[] = { NULL, NULL };
        alpnProtoArray[0] = ALPN_PROTOCOL_NAME;

        /* Pass the ALPN protocol name depending on the port being used.
         * Please see more details about the ALPN protocol for AWS IoT MQTT endpoint
         * in the link below.
         * https://aws.amazon.com/blogs/iot/mqtt-with-tls-client-authentication-on-port-443-why-it-is-useful-and-how-it-works/
         */
        tlsCredentials.pAlpnProtos = alpnProtoArray;
    }

    /* Initialize reconnect attempts and interval */
    BackoffAlgorithm_InitializeParams( &reconnectParams,
                                       CONNECTION_RETRY_BACKOFF_BASE_MS,
                                       CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
                                       CONNECTION_RETRY_MAX_ATTEMPTS );

    do
    {
        /* Establish a TLS session with the MQTT broker. This example connects
         * to the MQTT broker as specified in AWS_IOT_ENDPOINT and AWS_MQTT_PORT
         * at the demo config header. */
        LogDebug( ( "Establishing a TLS session to %.*s:%d.",
                    AWS_IOT_ENDPOINT_LENGTH,
                    AWS_IOT_ENDPOINT,
                    AWS_MQTT_PORT ) );

        tlsStatus = Mbedtls_Pkcs11_Connect( pNetworkContext,
                                            AWS_IOT_ENDPOINT,
                                            AWS_MQTT_PORT,
                                            &tlsCredentials,
                                            TRANSPORT_SEND_RECV_TIMEOUT_MS );

        if( tlsStatus == MBEDTLS_PKCS11_SUCCESS )
        {
            /* Connection successful. */
            returnStatus = true;
        }
        else
        {
            /* Generate a random number and get back-off value (in milliseconds) for the next connection retry. */
            backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &reconnectParams, generateRandomNumber(), &nextRetryBackOff );

            if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
            {
                LogError( ( "Connection to the broker failed, all attempts exhausted." ) );
            }
            else if( backoffAlgStatus == BackoffAlgorithmSuccess )
            {
                LogWarn( ( "Connection to the broker failed. Retrying connection "
                           "after %hu ms backoff.",
                           ( unsigned short ) nextRetryBackOff ) );
                Clock_SleepMs( nextRetryBackOff );
            }
        }
    } while( ( tlsStatus != MBEDTLS_PKCS11_SUCCESS ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

    return returnStatus;
}
/*-----------------------------------------------------------*/

static bool getNextFreeIndexForOutgoingPublishes( uint8_t * pIndex )
{
    bool returnStatus = false;
    uint8_t index = 0;

    assert( outgoingPublishPackets != NULL );
    assert( pIndex != NULL );

    for( index = 0; index < MAX_OUTGOING_PUBLISHES; index++ )
    {
        /* A free index is marked by invalid packet id. Check if the the index
         * has a free slot. */
        LogInfo( ( "free index looking for free slot." ) );
        if( outgoingPublishPackets[ index ].packetId == MQTT_PACKET_ID_INVALID )
        {
            LogInfo( ( "found it." ) );
            returnStatus = true;
            break;
        }
    }

    /* Copy the available index into the output param. */
    if( returnStatus == true )
    {
        *pIndex = index;
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishAt( uint8_t index )
{
    assert( outgoingPublishPackets != NULL );
    assert( index < MAX_OUTGOING_PUBLISHES );

    /* Clear the outgoing publish packet. */
    ( void ) memset( &( outgoingPublishPackets[ index ] ),
                     0x00,
                     sizeof( outgoingPublishPackets[ index ] ) );
}
/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishes( void )
{
    assert( outgoingPublishPackets != NULL );

    /* Clean up all the outgoing publish packets. */
    ( void ) memset( outgoingPublishPackets, 0x00, sizeof( outgoingPublishPackets ) );
}
/*-----------------------------------------------------------*/

static void cleanupOutgoingPublishWithPacketID( uint16_t packetId )
{
    uint8_t index = 0;

    assert( outgoingPublishPackets != NULL );
    assert( packetId != MQTT_PACKET_ID_INVALID );

    /* Clean up the saved outgoing publish with packet Id equal to packetId. */
    for( index = 0; index < MAX_OUTGOING_PUBLISHES; index++ )
    {
        if( outgoingPublishPackets[ index ].packetId == packetId )
        {
            cleanupOutgoingPublishAt( index );

            LogDebug( ( "Cleaned up outgoing publish packet with packet id %u.",
                        packetId ) );

            break;
        }
    }
}
/*-----------------------------------------------------------*/

void HandleOtherIncomingPacket( MQTTPacketInfo_t * pPacketInfo,
                                uint16_t packetIdentifier )
{
    /* Handle other packets. */
    switch( pPacketInfo->type )
    {
        case MQTT_PACKET_TYPE_SUBACK:
            LogInfo( ( "MQTT_PACKET_TYPE_SUBACK." ) );
            /* Make sure ACK packet identifier matches with Request packet identifier. */
            assert( globalSubscribePacketIdentifier == packetIdentifier );
            /* Update the global ACK packet identifier. */
            globalAckPacketIdentifier = packetIdentifier;
            break;

        case MQTT_PACKET_TYPE_UNSUBACK:
            LogInfo( ( "MQTT_PACKET_TYPE_UNSUBACK." ) );
            /* Make sure ACK packet identifier matches with Request packet identifier. */
            assert( globalUnsubscribePacketIdentifier == packetIdentifier );
            /* Update the global ACK packet identifier. */
            globalAckPacketIdentifier = packetIdentifier;
            break;

        case MQTT_PACKET_TYPE_PINGRESP:

            /* Nothing to be done from application as library handles
             * PINGRESP. */
            LogWarn( ( "PINGRESP should not be handled by the application "
                       "callback when using MQTT_ProcessLoop." ) );
            break;

        case MQTT_PACKET_TYPE_PUBACK:
            LogInfo( ( "PUBACK received for packet id %u.",
                       packetIdentifier ) );
            /* Cleanup publish packet when a PUBACK is received. */
            cleanupOutgoingPublishWithPacketID( packetIdentifier );
            /* Update the global ACK packet identifier. */
            globalAckPacketIdentifier = packetIdentifier;
            break;

        /* Any other packet type is invalid. */
        default:
            LogError( ( "Unknown packet type received:(%02x).",
                        pPacketInfo->type ) );
    }
}

void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo )
{
    ShadowMessageType_t messageType = ShadowMessageTypeMaxNum;
    const char * pThingName = NULL;
    uint8_t thingNameLength = 0U;
    const char * pShadowName = NULL;
    uint8_t shadowNameLength = 0U;
    uint16_t packetIdentifier;

    ( void ) pMqttContext;

    assert( pDeserializedInfo != NULL );
    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );

    packetIdentifier = pDeserializedInfo->packetIdentifier;

    /* Handle incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        assert( pDeserializedInfo->pPublishInfo != NULL );
        LogInfo( ( "pPublishInfo->pTopicName:%s.", pDeserializedInfo->pPublishInfo->pTopicName ) );

        /* Let the Device Shadow library tell us whether this is a device shadow message. */
        if( SHADOW_SUCCESS == Shadow_MatchTopicString( pDeserializedInfo->pPublishInfo->pTopicName,
                                                       pDeserializedInfo->pPublishInfo->topicNameLength,
                                                       &messageType,
                                                       &pThingName,
                                                       &thingNameLength,
                                                       &pShadowName,
                                                       &shadowNameLength ) )
        {
            /* Upon successful return, the messageType has been filled in. */
            if( messageType == ShadowMessageTypeUpdateDelta )
            {
                /* Handler function to process payload. */
                updateDeltaHandler( pDeserializedInfo->pPublishInfo );
            }
            else if( messageType == ShadowMessageTypeUpdateAccepted )
            {
                /* Handler function to process payload. */
                updateAcceptedHandler( pDeserializedInfo->pPublishInfo );
            }
            else if( messageType == ShadowMessageTypeUpdateDocuments )
            {
                LogInfo( ( "/update/documents json payload:%s.", ( const char * ) pDeserializedInfo->pPublishInfo->pPayload ) );
            }
            else if( messageType == ShadowMessageTypeUpdateRejected )
            {
                LogInfo( ( "/update/rejected json payload:%s.", ( const char * ) pDeserializedInfo->pPublishInfo->pPayload ) );
            }
            else if( messageType == ShadowMessageTypeDeleteAccepted )
            {
                LogInfo( ( "Received an MQTT incoming publish on /delete/accepted topic." ) );
                shadowDeleted = true;
                deleteResponseReceived = true;
            }
            else if( messageType == ShadowMessageTypeDeleteRejected )
            {
                /* Handler function to process payload. */
                deleteRejectedHandler( pDeserializedInfo->pPublishInfo );
                deleteResponseReceived = true;
            }
            else
            {
                LogInfo( ( "Other message type:%d !!", messageType ) );
            }
        }
        else
        {
            LogError( ( "Shadow_MatchTopicString parse failed:%s !!", ( const char * ) pDeserializedInfo->pPublishInfo->pTopicName ) );
            eventCallbackError = true;
        }
    }
    else
    {
        HandleOtherIncomingPacket( pPacketInfo, packetIdentifier );
    }
}


static void mqttCallback( MQTTContext_t * pMqttContext,
                          MQTTPacketInfo_t * pPacketInfo,
                          MQTTDeserializedInfo_t * pDeserializedInfo )
{
    uint16_t packetIdentifier;

    assert( pMqttContext != NULL );
    assert( pPacketInfo != NULL );
    assert( pDeserializedInfo != NULL );

    /* Suppress the unused parameter warning when asserts are disabled in
     * build. */
    ( void ) pMqttContext;

    packetIdentifier = pDeserializedInfo->packetIdentifier;

    /* Handle an incoming publish. The lower 4 bits of the publish packet
     * type is used for the dup, QoS, and retain flags. Hence masking
     * out the lower bits to check if the packet is publish. */
    if( ( pPacketInfo->type & 0xF0U ) == MQTT_PACKET_TYPE_PUBLISH )
    {
        assert( pDeserializedInfo->pPublishInfo != NULL );
        switch(aws_action)
        {
            case DEVICE_SHADOW:
            {
                LogInfo(( "Device Shadow process" ));
                ShadowMessageType_t messageType = ShadowMessageTypeMaxNum;
                const char * pThingName = NULL;
                uint8_t thingNameLength = 0U;
                const char * pShadowName = NULL;
                uint8_t shadowNameLength = 0U;
                uint16_t packetIdentifier;

                LogInfo( ( "pPublishInfo->pTopicName:%s.", pDeserializedInfo->pPublishInfo->pTopicName ) );

                /* Let the Device Shadow library tell us whether this is a device shadow message. */
                if( SHADOW_SUCCESS == Shadow_MatchTopicString( pDeserializedInfo->pPublishInfo->pTopicName,
                                                            pDeserializedInfo->pPublishInfo->topicNameLength,
                                                            &messageType,
                                                            &pThingName,
                                                            &thingNameLength,
                                                            &pShadowName,
                                                            &shadowNameLength ) )
                {
                    /* Upon successful return, the messageType has been filled in. */
                    if( messageType == ShadowMessageTypeUpdateDelta )
                    {
                        /* Handler function to process payload. */
                        updateDeltaHandler( pDeserializedInfo->pPublishInfo );
                    }
                    else if( messageType == ShadowMessageTypeUpdateAccepted )
                    {
                        /* Handler function to process payload. */
                        updateAcceptedHandler( pDeserializedInfo->pPublishInfo );
                    }
                    else if( messageType == ShadowMessageTypeUpdateDocuments )
                    {
                        LogInfo( ( "/update/documents json payload:%s.", ( const char * ) pDeserializedInfo->pPublishInfo->pPayload ) );
                    }
                    else if( messageType == ShadowMessageTypeUpdateRejected )
                    {
                        LogInfo( ( "/update/rejected json payload:%s.", ( const char * ) pDeserializedInfo->pPublishInfo->pPayload ) );
                    }
                    else if( messageType == ShadowMessageTypeDeleteAccepted )
                    {
                        LogInfo( ( "Received an MQTT incoming publish on /delete/accepted topic." ) );
                        shadowDeleted = true;
                        deleteResponseReceived = true;
                    }
                    else if( messageType == ShadowMessageTypeDeleteRejected )
                    {
                        /* Handler function to process payload. */
                        deleteRejectedHandler( pDeserializedInfo->pPublishInfo );
                        deleteResponseReceived = true;
                    }
                    else
                    {
                        LogInfo( ( "Other message type:%d !!", messageType ) );
                    }
                }
                else
                {
                    LogError( ( "Shadow_MatchTopicString parse failed:%s !!", ( const char * ) pDeserializedInfo->pPublishInfo->pTopicName ) );
                    eventCallbackError = true;
                }
            }
                break;
            case PROVISIONING:
            case PUB_SUB:
                LogInfo(( "Provisioning/Pub_sub process" ));
                /* Invoke the application callback for incoming publishes. */
                if( appPublishCallback != NULL )
                {
                    appPublishCallback( pDeserializedInfo->pPublishInfo, packetIdentifier );
                }
            default:
                break;
        }

    }
    else
    {
        /* Handle other packets. */
        switch( pPacketInfo->type )
        {
            case MQTT_PACKET_TYPE_SUBACK:
                LogDebug( ( "MQTT Packet type SUBACK received." ) );

                /* Make sure the ACK packet identifier matches with the request
                 * packet identifier. */
                assert( globalSubscribePacketIdentifier == packetIdentifier );

                /* Update the global ACK packet identifier. */
                globalAckPacketIdentifier = packetIdentifier;
                break;

            case MQTT_PACKET_TYPE_UNSUBACK:
                LogDebug( ( "MQTT Packet type UNSUBACK received." ) );

                /* Make sure the ACK packet identifier matches with the request
                 * packet identifier. */
                assert( globalUnsubscribePacketIdentifier == packetIdentifier );

                /* Update the global ACK packet identifier. */
                globalAckPacketIdentifier = packetIdentifier;
                break;

            case MQTT_PACKET_TYPE_PINGRESP:

                /* We do not expect to receive PINGRESP as we are using
                 * MQTT_ProcessLoop. */
                LogWarn( ( "PINGRESP should not be received by the application "
                           "callback when using MQTT_ProcessLoop." ) );
                break;

            case MQTT_PACKET_TYPE_PUBACK:
                LogDebug( ( "PUBACK received for packet id %u.",
                            packetIdentifier ) );

                /* Update the global ACK packet identifier. */
                globalAckPacketIdentifier = packetIdentifier;

                /* Cleanup the publish packet from the #outgoingPublishPackets
                 * array when a PUBACK is received. */
                cleanupOutgoingPublishWithPacketID( packetIdentifier );
                break;

            /* Any other packet type is invalid. */
            default:
                LogError( ( "Unknown packet type received:(%02x).",
                            pPacketInfo->type ) );
        }
    }
}
/*-----------------------------------------------------------*/

static bool handlePublishResend( MQTTContext_t * pMqttContext )
{
    bool returnStatus = false;
    MQTTStatus_t mqttStatus = MQTTSuccess;
    uint8_t index = 0U;

    assert( outgoingPublishPackets != NULL );

    /* Resend all the QoS1 publishes still in the #outgoingPublishPackets array.
     * These are the publishes that haven't received a PUBACK yet. When a PUBACK
     * is received, the corresponding publish is removed from the array. */
    for( index = 0U; index < MAX_OUTGOING_PUBLISHES; index++ )
    {
        if( outgoingPublishPackets[ index ].packetId != MQTT_PACKET_ID_INVALID )
        {
            outgoingPublishPackets[ index ].pubInfo.dup = true;

            LogDebug( ( "Sending duplicate PUBLISH with packet id %u.",
                        outgoingPublishPackets[ index ].packetId ) );
            mqttStatus = MQTT_Publish( pMqttContext,
                                       &outgoingPublishPackets[ index ].pubInfo,
                                       outgoingPublishPackets[ index ].packetId );

            if( mqttStatus != MQTTSuccess )
            {
                LogError( ( "Sending duplicate PUBLISH for packet id %u "
                            " failed with status %s.",
                            outgoingPublishPackets[ index ].packetId,
                            MQTT_Status_strerror( mqttStatus ) ) );
                break;
            }
            else
            {
                LogDebug( ( "Sent duplicate PUBLISH successfully for packet id %u.",
                            outgoingPublishPackets[ index ].packetId ) );
            }
        }
    }

    /* Were all the unacknowledged QoS1 publishes successfully re-sent? */
    if( index == MAX_OUTGOING_PUBLISHES )
    {
        returnStatus = true;
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

int parseLightCmd(char *msg, int len)
{
    JSONStatus_t result;
    char *value;
    size_t valueLen;

    // Calling JSON_Validate() is not necessary if the document is guaranteed to be valid.
    result = JSON_Validate( 
            msg, 
            len );

    if(result == JSONSuccess)
    {
        ESP_LOGI("MQTTParser", "JSON is valid. Parsing JSON");
        result = JSON_Search( 
            msg, 
            len, 
            "cmd", 
            3, 
            &value, 
            &valueLen );
    }
    
    // if(result == JSONSuccess)
    // {
    //     // The pointer "value" will point to a location in the "buffer".
    //     char save = value[ valueLen ];

    //     // After saving the character, set it to a null byte for printing.
    //     value[ valueLen ] = '\0';
        
    //     ESP_LOGI("MQTTParser", "Found: %s -> %s", "cmd", value);
    //     bool state = (strcmp(value, "ON") == 0) ? true : false;
    //     // mqttSetLightState(state);
    //     app_driver_button_set(state);

    //     // TODO: Check if the comparison is correct. 
        
    //     // Restore the character at the end of the value.
    //     value[ valueLen ] = save;

    // }
    // else
    // {
    //     result = JSONNotFound;
    // }
    return result;
}

/*-----------------------------------------------------------*/

void handleIncomingPublish( MQTTPublishInfo_t * pPublishInfo,
                                   uint16_t packetIdentifier )
{
    assert( pPublishInfo != NULL );

    /* Process incoming Publish. */
    LogInfo( ( "Incoming QOS : %d.", pPublishInfo->qos ) );

    /* Verify the received publish is for the topic we have subscribed to. */
    if( ( pPublishInfo->topicNameLength == (subscribedTopicNameLength) ) &&
        ( 0 == strncmp( subscribedTopicName,
                        pPublishInfo->pTopicName,
                        pPublishInfo->topicNameLength ) ) )
    {
        LogInfo( ( "Incoming Publish Topic Name: %.*s matches subscribed topic.\n"
                   "Incoming Publish message Packet Id is %u.\n"
                   "Incoming Publish Message : %.*s.\n\n",
                   pPublishInfo->topicNameLength,
                   pPublishInfo->pTopicName,
                   packetIdentifier,
                   ( int ) pPublishInfo->payloadLength,
                   ( const char * ) pPublishInfo->pPayload ) );

        JSONStatus_t res = uart_write(( const char * ) pPublishInfo->pPayload, ( size_t ) pPublishInfo->payloadLength);
        if (res != JSONSuccess)
        {
            LogError(("Error writing msg to uart"));
        }
        
        // int ret = parseLightCmd(( char * ) pPublishInfo->pPayload, ( int ) pPublishInfo->payloadLength);
        // if (ret == JSONSuccess)
        // {
        //     ESP_LOGI("MQTTParser", "JSON worked correctly.");
        // }
        // else
        // {
        //     ESP_LOGE("MQTTParser", "JSON didn't work.");
        // }
        
    }
    else
    {
        LogInfo( ( "Incoming Publish Topic Name: %.*s does not match subscribed topic.",
                   pPublishInfo->topicNameLength,
                   pPublishInfo->pTopicName ) );
        
        
    }
}

/*-----------------------------------------------------------*/

static void updateSubAckStatus( MQTTPacketInfo_t * pPacketInfo )
{
    uint8_t * pPayload = NULL;
    size_t pSize = 0;

    MQTTStatus_t mqttStatus = MQTT_GetSubAckStatusCodes( pPacketInfo, &pPayload, &pSize );

    /* MQTT_GetSubAckStatusCodes always returns success if called with packet info
     * from the event callback and non-NULL parameters. */
    assert( mqttStatus == MQTTSuccess );

    /* Suppress unused variable warning when asserts are disabled in build. */
    ( void ) mqttStatus;

    /* Demo only subscribes to one topic, so only one status code is returned. */
    globalSubAckStatus = ( MQTTSubAckStatus_t ) pPayload[ 0 ];
}

/*-----------------------------------------------------------*/

static int handleResubscribe( MQTTContext_t * pMqttContext )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTStatus_t mqttStatus = MQTTSuccess;
    BackoffAlgorithmStatus_t backoffAlgStatus = BackoffAlgorithmSuccess;
    BackoffAlgorithmContext_t retryParams;
    uint16_t nextRetryBackOff = 0U;

    assert( pMqttContext != NULL );

    /* Initialize retry attempts and interval. */
    BackoffAlgorithm_InitializeParams( &retryParams,
                                       CONNECTION_RETRY_BACKOFF_BASE_MS,
                                       CONNECTION_RETRY_MAX_BACKOFF_DELAY_MS,
                                       CONNECTION_RETRY_MAX_ATTEMPTS );

    do
    {
        /* Send SUBSCRIBE packet.
         * Note: reusing the value specified in globalSubscribePacketIdentifier is acceptable here
         * because this function is entered only after the receipt of a SUBACK, at which point
         * its associated packet id is free to use. */
        mqttStatus = MQTT_Subscribe( pMqttContext,
                                     pGlobalSubscriptionList,
                                     sizeof( pGlobalSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                     globalSubscribePacketIdentifier );

        if( mqttStatus != MQTTSuccess )
        {
            LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %s.",
                        MQTT_Status_strerror( mqttStatus ) ) );
            returnStatus = EXIT_FAILURE;
            break;
        }

        LogInfo( ( "SUBSCRIBE sent for topic %.*s to broker.\n\n",
                   MQTT_LIGHT_COMMAND_TOPIC_LENGTH,
                   MQTT_LIGHT_COMMAND_TOPIC ) );

        /* Process incoming packet. */
        returnStatus = waitForPacketAck( pMqttContext,
                                         globalSubscribePacketIdentifier,
                                         MQTT_PROCESS_LOOP_TIMEOUT_MS );

        if( returnStatus == EXIT_FAILURE )
        {
            break;
        }

        /* Check if recent subscription request has been rejected. globalSubAckStatus is updated
         * in eventCallback to reflect the status of the SUBACK sent by the broker. It represents
         * either the QoS level granted by the server upon subscription, or acknowledgement of
         * server rejection of the subscription request. */
        if( globalSubAckStatus == MQTTSubAckFailure )
        {
            /* Generate a random number and get back-off value (in milliseconds) for the next re-subscribe attempt. */
            backoffAlgStatus = BackoffAlgorithm_GetNextBackoff( &retryParams, generateRandomNumber(), &nextRetryBackOff );

            if( backoffAlgStatus == BackoffAlgorithmRetriesExhausted )
            {
                LogError( ( "Subscription to topic failed, all attempts exhausted." ) );
                returnStatus = EXIT_FAILURE;
            }
            else if( backoffAlgStatus == BackoffAlgorithmSuccess )
            {
                LogWarn( ( "Server rejected subscription request. Retrying "
                           "connection after %hu ms backoff.",
                           ( unsigned short ) nextRetryBackOff ) );
                Clock_SleepMs( nextRetryBackOff );
            }
        }
    } while( ( globalSubAckStatus == MQTTSubAckFailure ) && ( backoffAlgStatus == BackoffAlgorithmSuccess ) );

    return returnStatus;
}

/*-----------------------------------------------------------*/

static bool waitForPacketAck( MQTTContext_t * pMqttContext,
                              uint16_t usPacketIdentifier,
                              uint32_t ulTimeout )
{
    uint32_t ulMqttProcessLoopEntryTime;
    uint32_t ulMqttProcessLoopTimeoutTime;
    uint32_t ulCurrentTime;

    MQTTStatus_t eMqttStatus = MQTTSuccess;
    bool xStatus = false;

    /* Reset the ACK packet identifier being received. */
    globalAckPacketIdentifier = 0U;

    ulCurrentTime = pMqttContext->getTime();
    ulMqttProcessLoopEntryTime = ulCurrentTime;
    ulMqttProcessLoopTimeoutTime = ulCurrentTime + ulTimeout;

    /* Call MQTT_ProcessLoop multiple times until the expected packet ACK
     * is received, a timeout happens, or MQTT_ProcessLoop fails. */
    while( ( globalAckPacketIdentifier != usPacketIdentifier ) &&
           ( ulCurrentTime < ulMqttProcessLoopTimeoutTime ) &&
           ( eMqttStatus == MQTTSuccess || eMqttStatus == MQTTNeedMoreBytes ) )
    {
        /* Event callback will set #globalAckPacketIdentifier when receiving
         * appropriate packet. */
        eMqttStatus = MQTT_ProcessLoop( pMqttContext );
        ulCurrentTime = pMqttContext->getTime();
    }

    if( ( ( eMqttStatus != MQTTSuccess ) && ( eMqttStatus != MQTTNeedMoreBytes ) ) ||
        ( globalAckPacketIdentifier != usPacketIdentifier ) )
    {
        LogError( ( "MQTT_ProcessLoop failed to receive ACK packet: Expected ACK Packet ID=%02X, LoopDuration=%"PRIu32", Status=%s",
                    usPacketIdentifier,
                    ( ulCurrentTime - ulMqttProcessLoopEntryTime ),
                    MQTT_Status_strerror( eMqttStatus ) ) );
    }
    else
    {
        xStatus = true;
    }

    return xStatus;
}
/*-----------------------------------------------------------*/

bool EstablishMqttSession( MQTTPublishCallback_t publishCallback,
                           CK_SESSION_HANDLE p11Session,
                           char * pClientCertLabel,
                           char * pPrivateKeyLabel )
{
    bool returnStatus = false;
    MQTTStatus_t mqttStatus;
    MQTTConnectInfo_t connectInfo;
    MQTTFixedBuffer_t networkBuffer;
    TransportInterface_t transport = { NULL };
    bool createCleanSession = false;
    MQTTContext_t * pMqttContext = &mqttContext;
    NetworkContext_t * pNetworkContext = &networkContext;
    bool sessionPresent = false;

    assert( pMqttContext != NULL );
    assert( pNetworkContext != NULL );

    /* Initialize the mqtt context and network context. */
    ( void ) memset( pMqttContext, 0U, sizeof( MQTTContext_t ) );
    ( void ) memset( pNetworkContext, 0U, sizeof( NetworkContext_t ) );

    returnStatus = connectToBrokerWithBackoffRetries( pNetworkContext,
                                                      p11Session,
                                                      pClientCertLabel,
                                                      pPrivateKeyLabel );

    if( returnStatus != true )
    {
        /* Log an error to indicate connection failure after all
         * reconnect attempts are over. */
        LogError( ( "Failed to connect to MQTT broker %.*s.",
                    AWS_IOT_ENDPOINT_LENGTH,
                    AWS_IOT_ENDPOINT ) );
    }
    else
    {
        /* Fill in TransportInterface send and receive function pointers.
         * For this demo, TCP sockets are used to send and receive data
         * from the network. pNetworkContext is an SSL context for OpenSSL.*/
        transport.pNetworkContext = pNetworkContext;
        transport.send = Mbedtls_Pkcs11_Send;
        transport.recv = Mbedtls_Pkcs11_Recv;
        transport.writev = NULL;

        /* Fill the values for network buffer. */
        networkBuffer.pBuffer = buffer;
        networkBuffer.size = NETWORK_BUFFER_SIZE;

        /* Remember the publish callback supplied. */
        appPublishCallback = publishCallback;

        /* Initialize the MQTT library. */
        mqttStatus = MQTT_Init( pMqttContext,
                                &transport,
                                Clock_GetTimeMs,
                                mqttCallback,
                                &networkBuffer );

        if( mqttStatus != MQTTSuccess )
        {
            returnStatus = false;
            LogError( ( "MQTT_Init failed with status %s.",
                        MQTT_Status_strerror( mqttStatus ) ) );
        }
        else
        {
            mqttStatus = MQTT_InitStatefulQoS( pMqttContext,
                                               pOutgoingPublishRecords,
                                               OUTGOING_PUBLISH_RECORD_LEN,
                                               pIncomingPublishRecords,
                                               INCOMING_PUBLISH_RECORD_LEN );

            if( mqttStatus != MQTTSuccess )
            {
                returnStatus = false;
                LogError( ( "MQTT_InitStatefulQoS failed with status %s.",
                            MQTT_Status_strerror( mqttStatus ) ) );
            }
            else
            {
                /* Establish an MQTT session by sending a CONNECT packet. */

                /* If #createCleanSession is true, start with a clean session
                 * i.e. direct the MQTT broker to discard any previous session data.
                 * If #createCleanSession is false, direct the broker to attempt to
                 * reestablish a session which was already present. */
                connectInfo.cleanSession = createCleanSession;

                /* The client identifier is used to uniquely identify this MQTT client to
                 * the MQTT broker. In a production device the identifier can be something
                 * unique, such as a device serial number. */
                connectInfo.pClientIdentifier = CLIENT_IDENTIFIER;
                connectInfo.clientIdentifierLength = CLIENT_IDENTIFIER_LENGTH;

                /* The maximum time interval in seconds which is allowed to elapse
                 * between two Control Packets.
                 * It is the responsibility of the client to ensure that the interval between
                 * control packets being sent does not exceed the this keep-alive value. In the
                 * absence of sending any other control packets, the client MUST send a
                 * PINGREQ packet. */
                connectInfo.keepAliveSeconds = MQTT_KEEP_ALIVE_INTERVAL_SECONDS;

                /* Username and password for authentication. Not used in this demo. */
                connectInfo.pUserName = METRICS_STRING;
                connectInfo.userNameLength = METRICS_STRING_LENGTH;
                connectInfo.pPassword = NULL;
                connectInfo.passwordLength = 0U;

                /* Send an MQTT CONNECT packet to the broker. */
                mqttStatus = MQTT_Connect( pMqttContext,
                                           &connectInfo,
                                           NULL,
                                           CONNACK_RECV_TIMEOUT_MS,
                                           &sessionPresent );

                if( mqttStatus != MQTTSuccess )
                {
                    returnStatus = false;
                    LogError( ( "Connection with MQTT broker failed with status %s.",
                                MQTT_Status_strerror( mqttStatus ) ) );
                }
                else
                {
                    LogDebug( ( "MQTT connection successfully established with broker." ) );
                }
            }
        }

        if( returnStatus == true )
        {
            /* Keep a flag for indicating if MQTT session is established. This
             * flag will mark that an MQTT DISCONNECT has to be sent at the end
             * of the demo even if there are intermediate failures. */
            mqttSessionEstablished = true;
        }

        if( returnStatus == true )
        {
            /* Check if a session is present and if there are any outgoing
             * publishes that need to be resent. Resending unacknowledged
             * publishes is needed only if the broker is re-establishing a
             * session that was already present. */
            if( sessionPresent == true )
            {
                LogDebug( ( "An MQTT session with broker is re-established. "
                            "Resending unacked publishes." ) );

                /* Handle all the resend of publish messages. */
                returnStatus = handlePublishResend( &mqttContext );
            }
            else
            {
                LogDebug( ( "A clean MQTT connection is established."
                            " Cleaning up all the stored outgoing publishes." ) );

                /* Clean up the outgoing publishes waiting for ack as this new
                 * connection doesn't re-establish an existing session. */
                cleanupOutgoingPublishes();
            }
        }
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

bool DisconnectMqttSession( void )
{
    MQTTStatus_t mqttStatus = MQTTSuccess;
    bool returnStatus = false;
    MQTTContext_t * pMqttContext = &mqttContext;
    NetworkContext_t * pNetworkContext = &networkContext;

    assert( pMqttContext != NULL );
    assert( pNetworkContext != NULL );

    if( mqttSessionEstablished == true )
    {
        /* Send DISCONNECT. */
        mqttStatus = MQTT_Disconnect( pMqttContext );

        if( mqttStatus != MQTTSuccess )
        {
            LogError( ( "Sending MQTT DISCONNECT failed with status=%u.",
                        mqttStatus ) );
        }
        else
        {
            /* MQTT DISCONNECT sent successfully. */
            returnStatus = true;
        }
    }

    /* End TLS session, then close TCP connection. */
    ( void ) Mbedtls_Pkcs11_Disconnect( pNetworkContext );

    return returnStatus;
}
/*-----------------------------------------------------------*/

bool SubscribeToTopic( const char * pTopicFilter,
                       uint16_t topicFilterLength )
{
    bool returnStatus = false;
    MQTTStatus_t mqttStatus;
    MQTTContext_t * pMqttContext = &mqttContext;
    

    assert( pMqttContext != NULL );
    assert( pTopicFilter != NULL );
    assert( topicFilterLength > 0 );

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pGlobalSubscriptionList, 0x00, sizeof( pGlobalSubscriptionList ) );

    /* This example subscribes to only one topic and uses QOS1. */
    pGlobalSubscriptionList[ 0 ].qos = MQTTQoS1;
    pGlobalSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pGlobalSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    /* Generate packet identifier for the SUBSCRIBE packet. */
    globalSubscribePacketIdentifier = MQTT_GetPacketId( pMqttContext );

    /* Send SUBSCRIBE packet. */
    mqttStatus = MQTT_Subscribe( pMqttContext,
                                 pGlobalSubscriptionList,
                                 sizeof( pGlobalSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                 globalSubscribePacketIdentifier );

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send SUBSCRIBE packet to broker with error = %s.",
                    MQTT_Status_strerror( mqttStatus ) ) );
    }
    else
    {
        LogDebug( ( "SUBSCRIBE topic %.*s to broker.",
                    topicFilterLength,
                    pTopicFilter ) );

        /* Process incoming packet from the broker. Acknowledgment for subscription
         * ( SUBACK ) will be received here. However after sending the subscribe, the
         * client may receive a publish before it receives a subscribe ack. Since this
         * demo is subscribing to the topic to which no one is publishing, probability
         * of receiving publish message before subscribe ack is zero; but application
         * must be ready to receive any packet. This demo uses MQTT_ProcessLoop to
         * receive packet from network. */
        returnStatus = waitForPacketAck( pMqttContext,
                                         globalSubscribePacketIdentifier,
                                         MQTT_PROCESS_LOOP_TIMEOUT_MS );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

int subscribeToLightTopic( const char * pTopicFilter,
                       uint16_t topicFilterLength )
{
    int returnStatus = EXIT_SUCCESS;
    MQTTContext_t * pMqttContext = &mqttContext;
    subscribedTopicNameLength = topicFilterLength + MQTT_LIGHT_COMMAND_TOPIC_LENGTH;

    memcpy(subscribedTopicName, pTopicFilter, subscribedTopicNameLength);
    strcat(subscribedTopicName, MQTT_LIGHT_COMMAND_TOPIC);

    const uint8_t MAX_SUBSCRIPTION_TRIES = 5;
    for (uint8_t i = 0; i < MAX_SUBSCRIPTION_TRIES; i++)
    {
        if( returnStatus == EXIT_SUCCESS )
        {
            /* The client is now connected to the broker. Subscribe to the topic
            * as specified in MQTT_LIGHT_COMMAND_TOPIC at the top of this file by sending a
            * subscribe packet. This client will then publish to the same topic it
            * subscribed to, so it will expect all the messages it sends to the broker
            * to be sent back to it from the broker. This demo uses QOS1 in Subscribe,
            * therefore, the Publish messages received from the broker will have QOS1. */
            LogInfo( ( "Subscribing to the MQTT topic %.*s.",
                    subscribedTopicNameLength,
                    subscribedTopicName ) );
            
            returnStatus = SubscribeToTopic( subscribedTopicName, subscribedTopicNameLength );
        }

        /* Check if recent subscription request has been rejected. globalSubAckStatus is updated
        * in eventCallback to reflect the status of the SUBACK sent by the broker. */
        if( ( returnStatus == EXIT_SUCCESS ) && ( globalSubAckStatus == MQTTSubAckFailure ) )
        {
            /* If server rejected the subscription request, attempt to resubscribe to topic.
             * Attempts are made according to the exponential backoff retry strategy
             * implemented in retryUtils. */
            LogInfo( ( "Server rejected initial subscription request. Attempting to re-subscribe to topic %.*s.",
                       subscribedTopicNameLength,
                       subscribedTopicName ) );
            returnStatus = handleResubscribe( pMqttContext );
        }

        if (returnStatus == EXIT_SUCCESS)
        {
            LogInfo( ( "Successfully subscribed!" ) );
            break;
        }
           LogInfo( ( "Failed, try again! %d",  returnStatus ) );
    }

    return returnStatus;
}

/*-----------------------------------------------------------*/

bool UnsubscribeFromTopic( const char * pTopicFilter,
                           uint16_t topicFilterLength )
{
    bool returnStatus = false;
    MQTTStatus_t mqttStatus;
    MQTTContext_t * pMqttContext = &mqttContext;

    assert( pMqttContext != NULL );
    assert( pTopicFilter != NULL );
    assert( topicFilterLength > 0 );

    /* Start with everything at 0. */
    ( void ) memset( ( void * ) pGlobalSubscriptionList, 0x00, sizeof( pGlobalSubscriptionList ) );

    /* This example subscribes to only one topic and uses QOS1. */
    pGlobalSubscriptionList[ 0 ].qos = MQTTQoS1;
    pGlobalSubscriptionList[ 0 ].pTopicFilter = pTopicFilter;
    pGlobalSubscriptionList[ 0 ].topicFilterLength = topicFilterLength;

    /* Generate packet identifier for the UNSUBSCRIBE packet. */
    globalUnsubscribePacketIdentifier = MQTT_GetPacketId( pMqttContext );

    /* Send UNSUBSCRIBE packet. */
    mqttStatus = MQTT_Unsubscribe( pMqttContext,
                                   pGlobalSubscriptionList,
                                   sizeof( pGlobalSubscriptionList ) / sizeof( MQTTSubscribeInfo_t ),
                                   globalUnsubscribePacketIdentifier );

    if( mqttStatus != MQTTSuccess )
    {
        LogError( ( "Failed to send UNSUBSCRIBE packet to broker with error = %s.",
                    MQTT_Status_strerror( mqttStatus ) ) );
    }
    else
    {
        LogDebug( ( "UNSUBSCRIBE sent topic %.*s to broker.",
                    topicFilterLength,
                    pTopicFilter ) );

        /* Process incoming packet from the broker. Acknowledgment for unsubscribe
         * operation ( UNSUBACK ) will be received here. This demo uses
         * MQTT_ProcessLoop to receive packet from network. */
        returnStatus = waitForPacketAck( pMqttContext,
                                         globalUnsubscribePacketIdentifier,
                                         MQTT_PROCESS_LOOP_TIMEOUT_MS );
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

bool PublishToTopic( const char * pTopicFilter,
                     uint16_t topicFilterLength,
                     const char * pPayload,
                     size_t payloadLength )
{
    bool returnStatus = false;
    MQTTStatus_t mqttStatus = MQTTSuccess;
    uint8_t publishIndex = MAX_OUTGOING_PUBLISHES;
    MQTTContext_t * pMqttContext = &mqttContext;

    assert( pMqttContext != NULL );
    assert( pTopicFilter != NULL );
    assert( topicFilterLength > 0 );

    /* Get the next free index for the outgoing publish. All QoS1 outgoing
     * publishes are stored until a PUBACK is received. These messages are
     * stored for supporting a resend if a network connection is broken before
     * receiving a PUBACK. */
    returnStatus = getNextFreeIndexForOutgoingPublishes( &publishIndex );
    LogInfo( ( "keep working" ) );
    if( returnStatus == false )
    {
        LogError( ( "Unable to find a free spot for outgoing PUBLISH message." ) );
    }
    else
    {
        LogInfo( ( "Published payload: %.*s",
                    ( int ) payloadLength,
                    ( const char * ) pPayload ) );

        /* This example publishes to only one topic and uses QOS1. */
        outgoingPublishPackets[ publishIndex ].pubInfo.qos = MQTTQoS1;
        outgoingPublishPackets[ publishIndex ].pubInfo.pTopicName = pTopicFilter;
        outgoingPublishPackets[ publishIndex ].pubInfo.topicNameLength = topicFilterLength;
        outgoingPublishPackets[ publishIndex ].pubInfo.pPayload = pPayload;
        outgoingPublishPackets[ publishIndex ].pubInfo.payloadLength = payloadLength;

        /* Get a new packet id. */
        outgoingPublishPackets[ publishIndex ].packetId = MQTT_GetPacketId( pMqttContext );

        /* Send PUBLISH packet. */
        mqttStatus = MQTT_Publish( pMqttContext,
                                   &outgoingPublishPackets[ publishIndex ].pubInfo,
                                   outgoingPublishPackets[ publishIndex ].packetId );

        if( mqttStatus != MQTTSuccess )
        {
            LogInfo( ( "Failed to send PUBLISH packet to broker with error = %s.",
                        MQTT_Status_strerror( mqttStatus ) ) );
            cleanupOutgoingPublishAt( publishIndex );
            returnStatus = false;
        }
        else
        {
            LogInfo( ( "PUBLISH sent for topic %.*s to broker with packet ID %u.",
                        topicFilterLength,
                        pTopicFilter,
                        outgoingPublishPackets[ publishIndex ].packetId ) );
        }
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/

bool ProcessLoopWithTimeout( void )
{
    uint32_t ulMqttProcessLoopTimeoutTime;
    uint32_t ulCurrentTime;

    MQTTStatus_t eMqttStatus = MQTTSuccess;
    bool returnStatus = false;

    ulCurrentTime = mqttContext.getTime();
    ulMqttProcessLoopTimeoutTime = ulCurrentTime + MQTT_PROCESS_LOOP_TIMEOUT_MS;

    /* Call MQTT_ProcessLoop multiple times until the timeout expires or
     * #MQTT_ProcessLoop fails. */
    while( ( ulCurrentTime < ulMqttProcessLoopTimeoutTime ) &&
           ( eMqttStatus == MQTTSuccess || eMqttStatus == MQTTNeedMoreBytes ) )
    {
        eMqttStatus = MQTT_ProcessLoop( &mqttContext );
        ulCurrentTime = mqttContext.getTime();
    }

    if( ( eMqttStatus != MQTTSuccess ) && ( eMqttStatus != MQTTNeedMoreBytes ) )
    {
        LogError( ( "MQTT_ProcessLoop returned with status = %s.",
                    MQTT_Status_strerror( eMqttStatus ) ) );
    }
    else
    {
        LogDebug( ( "MQTT_ProcessLoop successful." ) );
        returnStatus = true;
    }

    return returnStatus;
}
/*-----------------------------------------------------------*/
