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

#ifndef MQTT_OPERATIONS_H_
#define MQTT_OPERATIONS_H_

/* MQTT API header. */
#include "core_mqtt.h"

/* corePKCS11 include. */
#include "core_pkcs11.h"

/**
 * @brief The topic to subscribe and publish to in the example.
 *
 * The topic name starts with the client identifier to ensure that each demo
 * interacts with a unique topic name.
 */
#define MQTT_LIGHT_COMMAND_TOPIC          "/light/cmd"

/**
 * @brief Length of client MQTT topic.
 */
#define MQTT_LIGHT_COMMAND_TOPIC_LENGTH   ( ( uint16_t ) ( sizeof( MQTT_LIGHT_COMMAND_TOPIC ) - 1 ) )

/**
 * @brief The topic to subscribe and publish to in the example.
 *
 * The topic name starts with the client identifier to ensure that each demo
 * interacts with a unique topic name.
 */
#define MQTT_LIGHT_TOPIC                  "/light/status"

/**
 * @brief Length of client MQTT topic.
 */
#define MQTT_LIGHT_TOPIC_LENGTH           ( ( uint16_t ) ( sizeof( MQTT_LIGHT_TOPIC ) - 1 ) )

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


typedef enum
{
    PROVISIONING,
    PUB_SUB,
    DEVICE_SHADOW,
    INVALID
} aws_mqtt_state_t;

/**
 * @brief Application callback type to handle the incoming publishes.
 *
 * @param[in] pPublishInfo Pointer to publish info of the incoming publish.
 * @param[in] packetIdentifier Packet identifier of the incoming publish.
 */
typedef void (* MQTTPublishCallback_t )( MQTTPublishInfo_t * pPublishInfo,
                                         uint16_t packetIdentifier );

/**
 * @brief Establish a MQTT connection.
 *
 * @param[in] publishCallback The callback function to receive incoming
 * publishes from the MQTT broker.
 * @param[in] p11Session The PKCS #11 session to use.
 * @param[in] pClientCertLabel The client certificate PKCS #11 label to use.
 * @param[in] pPrivateKeyLabel The private key PKCS #11 label for the client certificate.
 *
 * @return true if an MQTT session is established;
 * false otherwise.
 */
bool EstablishMqttSession( MQTTPublishCallback_t publishCallback,
                           CK_SESSION_HANDLE p11Session,
                           char * pClientCertLabel,
                           char * pPrivateKeyLabel );

/**
 * @brief Disconnect the MQTT connection.
 *
 * @return true if the MQTT session was successfully disconnected;
 * false otherwise.
 */
bool DisconnectMqttSession( void );

/**
 * @brief Subscribe to a MQTT topic filter.
 *
 * @param[in] pTopicFilter The topic filter to subscribe to.
 * @param[in] topicFilterLength Length of the topic buffer.
 *
 * @return true if subscribe operation was successful;
 * false otherwise.
 */
bool SubscribeToTopic( const char * pTopicFilter,
                       uint16_t topicFilterLength );

int subscribeToLightTopic( const char * pTopicFilter,
                       uint16_t topicFilterLength );

void handleIncomingPublish( MQTTPublishInfo_t * pPublishInfo,
            uint16_t packetIdentifier );

/**
 * @brief Unsubscribe from a MQTT topic filter.
 *
 * @param[in] pTopicFilter The topic filter to unsubscribe from.
 * @param[in] topicFilterLength Length of the topic buffer.
 *
 * @return true if unsubscribe operation was successful;
 * false otherwise.
 */
bool UnsubscribeFromTopic( const char * pTopicFilter,
                           uint16_t topicFilterLength );

/**
 * @brief Publish a message to a MQTT topic.
 *
 * @param[in] pTopic The topic to publish the message on.
 * @param[in] topicLength Length of the topic.
 * @param[in] pMessage The message to publish.
 * @param[in] messageLength Length of the message.
 *
 * @return true if PUBLISH was successfully sent;
 * false otherwise.
 */
bool PublishToTopic( const char * pTopic,
                     uint16_t topicLength,
                     const char * pMessage,
                     size_t messageLength );

/**
 * @brief Invoke the core MQTT library's process loop function.
 *
 * @return true if process loop was successful;
 * false otherwise.
 */
bool ProcessLoopWithTimeout( void );

void set_aws_action(aws_mqtt_state_t action);
int device_shadow_demo(void);
void eventCallback( MQTTContext_t * pMqttContext,
                           MQTTPacketInfo_t * pPacketInfo,
                           MQTTDeserializedInfo_t * pDeserializedInfo );
/**
 * @brief Handle the incoming packet if it's not related to the device shadow.
 *
 * @param[in] pPacketInfo Packet Info pointer for the incoming packet.
 * @param[in] packetIdentifier Packet identifier of the incoming packet.
 */
void HandleOtherIncomingPacket( MQTTPacketInfo_t * pPacketInfo,
                                uint16_t packetIdentifier );


#endif /* ifndef MQTT_OPERATIONS_H_ */
