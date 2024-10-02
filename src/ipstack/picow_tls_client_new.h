//
// Created by abhin on 02/10/2024.
//

#ifndef RP2040_FREERTOS_IRQ_PICOW_TLS_CLIENT_NEW_H
#define RP2040_FREERTOS_IRQ_PICOW_TLS_CLIENT_NEW_H

//
// Created by abhin on 02/10/2024.
//

/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <mbedtls/debug.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "ipstack/tls_common.h"

#if 1
//#define TLS_CLIENT_SERVER        "18.198.188.151"
#define TLS_CLIENT_SERVER        "api.thingspeak.com"
#define TLS_CLIENT_HTTP_REQUEST  "GET /talkbacks/53261/commands/execute.json?api_key=ZZ4SW85BXQ6W18HV HTTP/1.1\r\n" \
                                 "Host: " TLS_CLIENT_SERVER "\r\n" \
                                 "Connection: close\r\n" \
                                 "\r\n"
#define TLS_CLIENT_TIMEOUT_SECS  15
#endif
// GET https://api.thingspeak.com/talkbacks/52920/commands/COMMAND_ID.json?api_key=371DAWENQKI6J8DD
#define TLS_JOES_SERVER "-----BEGIN CERTIFICATE-----\n\
MIIDXTCCAkWgAwIBAgIUPp2A/waMZh3cPqpQ9xqhu5d3lA0wDQYJKoZIhvcNAQEL\n\
BQAwPjEXMBUGA1UEAwwOMTguMTk4LjE4OC4xNTExCzAJBgNVBAYTAlVTMRYwFAYD\n\
VQQHDA1TYW4gRnJhbnNpc2NvMB4XDTI0MDYxMjExMjEwM1oXDTI1MDYwMzExMjEw\n\
M1owPjEXMBUGA1UEAwwOMTguMTk4LjE4OC4xNTExCzAJBgNVBAYTAlVTMRYwFAYD\n\
VQQHDA1TYW4gRnJhbnNpc2NvMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC\n\
AQEAuWejVUsk/cYJHp+vOYkBzWdSvHlYWbkdWf2HnHy8qYLMJ/sQyYcL9XEv85dq\n\
HrOCuS1vp7UC0YxnfFQ2tmQ9PNqaEUOOvIwJUOK5jutK+H16gFTbOHM4EdcY1WkJ\n\
43jffHSiq7RRiAUhTwh+2ISCMAxPlXcOiEPoUrFauOKTRMvBFcfgqFHbOdCA9X5z\n\
ol0JzdeV9MMYtSWhMi+F+DJBMrNDxQhymJFyt6p9ft0v8m5B5mTKGuhppMCUSHNP\n\
ij3WQkTnByOynUAQ3WG/LaSNg1ItqPVf9/RHKWWViRAwB4DEfOoeKkM2EFHqxHLw\n\
bjybmleFnxQguzX8+oEe9NKGTQIDAQABo1MwUTAdBgNVHQ4EFgQUx8JPYn//MjiT\n\
4o38VAS4advRrtQwHwYDVR0jBBgwFoAUx8JPYn//MjiT4o38VAS4advRrtQwDwYD\n\
VR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEADqaV5F+HhRqL35O5sycZ\n\
E4Gn8KewK/BDWkmQzqP5+w1PZ9bUGiSY49ftT2EGiLoOawnztkGBWX1Sv520T5qE\n\
wvB/rDzxOU/v9OIUTqCX7X68zVoN7A7r1iP6o66mnfgu9xDSk0ROZ73bYtaWL/Qq\n\
SJWBN1pPY2ekFxYNwBg8C1DTJ3H51H6R7kN0wze7lMN1tglrvLl1e60a8rm+QNwX\n\
FzQGTenLecgMGeXVsIGhnivQTvF2HN+EcXHs8O8LzHpX7fpt/KcsBx+kYmltkdJW\n\
QaFXAdvGJkhKEwJVn3qETVlTdtSKpc/1KdXq/01HuX7cPfXVMGJVXuJAk6Yxgx8z\n\
Ew==\n\
-----END CERTIFICATE-----\n"

#define WIFI_SSID "Nadim"
#define WIFI_PASSWORD "nadimahmed"

void tls_test(void);



#endif //RP2040_FREERTOS_IRQ_PICOW_TLS_CLIENT_NEW_H
