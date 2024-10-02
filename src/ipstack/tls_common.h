//
// Created by abhin on 02/10/2024.
//

#ifndef RP2040_FREERTOS_IRQ_TLS_COMMON_H
#define RP2040_FREERTOS_IRQ_TLS_COMMON_H


bool run_tls_client_test(const uint8_t *cert, size_t cert_len, const char *server, const char *request, int timeout);

#endif //RP2040_FREERTOS_IRQ_TLS_COMMON_H
