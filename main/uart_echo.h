#ifndef UART_ECHO
#define UART_ECHO
#include <stdio.h>
#include <stdbool.h>

/**
 * This is an example which echos any data it receives on configured UART back to the sender,
 * with hardware flow control turned off. It does not use UART driver event queue.
 *
 * - Port: configured UART
 * - Receive (Rx) buffer: on
 * - Transmit (Tx) buffer: off
 * - Flow control: off
 * - Event queue: off
 * - Pin assignment: see defines below (See Kconfig)
 */

#define BUF_SIZE (1024)

#define UART_PORT_NUM 2
#define UART_BAUD_RATE 115200
#define UART_RXD 5              // Pin number RX 
#define UART_TXD 4              // Pin number TX
#define TASK_STACK_SIZE 2048

#define ECHO_TEST_TXD (UART_TXD)
#define ECHO_TEST_RXD (UART_RXD)
#define ECHO_TEST_RTS (UART_PIN_NO_CHANGE)
#define ECHO_TEST_CTS (UART_PIN_NO_CHANGE)

#define ECHO_UART_PORT_NUM      (UART_PORT_NUM)
#define ECHO_UART_BAUD_RATE     (UART_BAUD_RATE)
#define ECHO_TASK_STACK_SIZE    (TASK_STACK_SIZE)

void uart_init(void);

bool uart_listen(char *rx_buf, size_t l);

#endif // UART_ECHO 