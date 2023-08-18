#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
  struct sockaddr_in addr;
  const SSL_METHOD *method;
  SSL_CTX *ssl_ctx = NULL;
  SSL *ssl = NULL;
  int fd = -1;
  char *txbuf = NULL;
  size_t txcap = 0;
  int txlen;
  char rxbuf[128];
  size_t rxcap = sizeof(rxbuf);
  int rxlen;
  char *server_ip = "127.0.0.1";
  char *server_port = "443";

  if (argc == 2) {
    server_ip = argv[1];
    server_port = strstr(argv[1], ":");
    if (server_port != NULL)
      *server_port++ = '\0';
    else
      server_port = "443";
  }

  method = NTLS_client_method();
  ssl_ctx = SSL_CTX_new(method);
  if (ssl_ctx == NULL) {
    perror("Unable to create SSL context");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  SSL_CTX_enable_ntls(ssl_ctx);
  SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_NONE, NULL);

  fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("Unable to create socket");
    exit(EXIT_FAILURE);
  }

  addr.sin_family = AF_INET;
  inet_pton(AF_INET, server_ip, &addr.sin_addr.s_addr);
  addr.sin_port = htons(atoi(server_port));

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("Unable to TCP connect to server");
    goto exit;
  } else {
    printf("TCP connection to server successful\n");
  }

  /* Create client SSL structure using dedicated client socket */
  ssl = SSL_new(ssl_ctx);
  SSL_set_fd(ssl, fd);
  SSL_CTX_set_ciphersuites(ssl_ctx, "TLS_SM4_CCM_SM3");
  if (SSL_connect(ssl) == 1) {
    printf("TLCP Protocol %s\n\n", SSL_get_cipher(ssl));
    printf("TLCP connection to server successful\n\n");

    /* Loop to send input from keyboard */
    while (1) {
      /* Get a line of input */
      txlen = getline(&txbuf, &txcap, stdin);
      /* Exit loop on error */
      if (txlen < 0 || txbuf == NULL) {
        break;
      }
      /* Exit loop if just a carriage return */
      if (txbuf[0] == '\n') {
        break;
      }
      /* Send it to the server */
      if (SSL_write(ssl, txbuf, txlen) <= 0) {
        printf("Server closed connection\n");
        ERR_print_errors_fp(stderr);
        break;
      }

      /* Wait for the echo */
      rxlen = SSL_read(ssl, rxbuf, rxcap);
      if (rxlen <= 0) {
        printf("Server closed connection\n");
        ERR_print_errors_fp(stderr);
        break;
      } else {
        /* Show it */
        rxbuf[rxlen] = 0;
        printf("Received: %s", rxbuf);
      }
    }
    printf("Client exiting...\n");
  } else {

    printf("SSL connection to server failed\n\n");

    ERR_print_errors_fp(stderr);
  }
exit:
  if (ssl != NULL) {
    SSL_shutdown(ssl);
    SSL_free(ssl);
  }
  SSL_CTX_free(ssl_ctx);

  if (fd != -1)
    close(fd);
  if (txbuf != NULL && txcap > 0)
    free(txbuf);

  return 0;
}
// gcc client.c  -I/opt/tongsuo/include/ -L/opt/tongsuo/lib64/ -lssl -lcrypto
// -Wl,-rpath=/opt/tongsuo/lib64 -o client
