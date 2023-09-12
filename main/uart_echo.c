#include "uart_echo.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include <stdio.h>

// Configure a buffer for the incoming data
uint8_t data[BUF_SIZE];

void uart_init(void)
{
    /* Configure parameters of an UART driver,
     * communication pins and install the driver */
    uart_config_t uart_config = {
        .baud_rate = ECHO_UART_BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity    = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .source_clk = UART_SCLK_DEFAULT,
    };
    int intr_alloc_flags = 0;

#if CONFIG_UART_ISR_IN_IRAM
    intr_alloc_flags = ESP_INTR_FLAG_IRAM;
#endif

    ESP_ERROR_CHECK(uart_driver_install(ECHO_UART_PORT_NUM, BUF_SIZE * 2, 0, 0, NULL, intr_alloc_flags));
    ESP_ERROR_CHECK(uart_param_config(ECHO_UART_PORT_NUM, &uart_config));
    ESP_ERROR_CHECK(uart_set_pin(ECHO_UART_PORT_NUM, ECHO_TEST_TXD, ECHO_TEST_RXD, ECHO_TEST_RTS, ECHO_TEST_CTS));
}

bool uart_listen(char *rx_buff, size_t l)
{
    bool ret = false;
    // Read data from the UART
    int len = uart_read_bytes(ECHO_UART_PORT_NUM, data, (BUF_SIZE - 1), 20 / portTICK_PERIOD_MS);
    // Write data back to the UART
    uart_write_bytes(ECHO_UART_PORT_NUM, (const char *) data, len);
    if (len) {
        data[len] = '\0';
        ESP_LOGI("uart", "Recv str: %s", (char *) data);
        ret = true;
    }
    return ret;
}