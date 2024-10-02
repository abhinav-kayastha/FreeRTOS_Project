//
// Created by abhin on 02/10/2024.
//

#include <iostream>
#include <string>
#include <cassert>
#include <cstdlib>
#include <cstring>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/pbuf.h"
#include "lwip/altcp_tcp.h"
#include "lwip/altcp_tls.h"
#include "lwip/dns.h"
#include "FreeRTOS.h"
#include "task.h"
#include "tls_common.h"

class TLSClient {
public:
    TLSClient(const uint8_t *cert, size_t cert_len, const std::string &server, const std::string &request, int timeout)
            : cert(cert), cert_len(cert_len), server(server), request(request), timeout(timeout), complete(false), error(0) {
        tls_config = altcp_tls_create_config_client(cert, cert_len);
        assert(tls_config);
        mbedtls_ssl_conf_authmode((mbedtls_ssl_config *)tls_config, MBEDTLS_SSL_VERIFY_OPTIONAL);
    }

    ~TLSClient() {
        altcp_tls_free_config(tls_config);
    }

    bool run() {
        if (!init()) {
            return false;
        }
        while (!complete) {
#if PICO_CYW43_ARCH_POLL
            cyw43_arch_poll();
            cyw43_arch_wait_for_work_until(make_timeout_time_ms(1000));
#else
            vTaskDelay(1000);
#endif
        }
        return error == 0;
    }

private:
    const uint8_t *cert;
    size_t cert_len;
    std::string server;
    std::string request;
    int timeout;
    bool complete;
    int error;
    struct altcp_tls_config *tls_config;
    struct altcp_pcb *pcb;

    bool init() {
        pcb = altcp_tls_new(tls_config, IPADDR_TYPE_ANY);
        if (!pcb) {
            std::cerr << "failed to create pcb" << std::endl;
            return false;
        }

        altcp_arg(pcb, this);
        altcp_poll(pcb, tls_client_poll, timeout * 2);
        altcp_recv(pcb, tls_client_recv);
        altcp_err(pcb, tls_client_err);

        mbedtls_ssl_set_hostname(static_cast<mbedtls_ssl_context*>(altcp_tls_context(pcb)), server.c_str());
        std::cout << "resolving " << server << std::endl;

        cyw43_arch_lwip_begin();
        ip_addr_t server_ip;
        err_t err = dns_gethostbyname(server.c_str(), &server_ip, tls_client_dns_found, this);
        if (err == ERR_OK) {
            tls_client_connect_to_server_ip(&server_ip);
        } else if (err != ERR_INPROGRESS) {
            std::cerr << "error initiating DNS resolving, err=" << err << std::endl;
            close();
        }
        cyw43_arch_lwip_end();

        return err == ERR_OK || err == ERR_INPROGRESS;
    }

    void close() {
        complete = true;
        if (pcb != nullptr) {
            altcp_arg(pcb, nullptr);
            altcp_poll(pcb, nullptr, 0);
            altcp_recv(pcb, nullptr);
            altcp_err(pcb, nullptr);
            err_t err = altcp_close(pcb);
            if (err != ERR_OK) {
                std::cerr << "close failed " << err << ", calling abort" << std::endl;
                altcp_abort(pcb);
            }
            pcb = nullptr;
        }
    }

    static err_t tls_client_poll(void *arg, struct altcp_pcb *pcb) {
        TLSClient *client = static_cast<TLSClient *>(arg);
        std::cout << "timed out" << std::endl;
        client->error = PICO_ERROR_TIMEOUT;
        client->close();
        return ERR_OK;
    }

    static void tls_client_err(void *arg, err_t err) {
        TLSClient *client = static_cast<TLSClient *>(arg);
        std::cerr << "tls_client_err " << err << std::endl;
        client->close();
        client->error = PICO_ERROR_GENERIC;
    }

    static err_t tls_client_recv(void *arg, struct altcp_pcb *pcb, struct pbuf *p, err_t err) {
        TLSClient *client = static_cast<TLSClient *>(arg);
        if (!p) {
            std::cout << "connection closed" << std::endl;
            client->close();
            return ERR_OK;
        }

        if (p->tot_len > 0) {
            char *buf = (char *)malloc(p->tot_len + 1);
            pbuf_copy_partial(p, buf, p->tot_len, 0);
            buf[p->tot_len] = 0;

            std::cout << "***\nnew data received from server:\n***\n\n" << buf << std::endl;
            free(buf);

            altcp_recved(pcb, p->tot_len);
        }
        pbuf_free(p);

        return ERR_OK;
    }

    static void tls_client_dns_found(const char *hostname, const ip_addr_t *ipaddr, void *arg) {
        TLSClient *client = static_cast<TLSClient *>(arg);
        if (ipaddr) {
            std::cout << "DNS resolving complete" << std::endl;
            client->tls_client_connect_to_server_ip(ipaddr);
        } else {
            std::cerr << "error resolving hostname " << hostname << std::endl;
            client->close();
        }
    }

    void tls_client_connect_to_server_ip(const ip_addr_t *ipaddr) {
        err_t err;
        u16_t port = 443;

        std::cout << "connecting to server IP " << ipaddr_ntoa(ipaddr) << " port " << port << std::endl;
        err = altcp_connect(pcb, ipaddr, port, tls_client_connected);
        if (err != ERR_OK) {
            std::cerr << "error initiating connect, err=" << err << std::endl;
            close();
        }
    }

    static err_t tls_client_connected(void *arg, struct altcp_pcb *pcb, err_t err) {
        TLSClient *client = static_cast<TLSClient *>(arg);
        if (err != ERR_OK) {
            std::cerr << "connect failed " << err << std::endl;
            return client->close(), ERR_OK;
        }

        std::cout << "connected to server, sending request" << std::endl;
        err = altcp_write(client->pcb, client->request.c_str(), client->request.length(), TCP_WRITE_FLAG_COPY);
        if (err != ERR_OK) {
            std::cerr << "error writing data, err=" << err << std::endl;
            return client->close(), ERR_OK;
        }

        return ERR_OK;
    }
};

bool run_tls_client_test(const uint8_t *cert, size_t cert_len, const char *server, const char *request, int timeout) {
    TLSClient client(cert, cert_len, server, request, timeout);
    return client.run();
}