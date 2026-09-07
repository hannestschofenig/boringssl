// Minimal UDP peer used to exercise BoringSSL's DTLS 1.3 implementation.

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>

namespace {

struct Options {
  bool server = false;
  std::string host = "127.0.0.1";
  int port = 0;
  std::string cert;
  std::string key;
  std::string ca;
  std::string curves;
  int timeout_seconds = 20;
};

void Usage(const char *program) {
  fprintf(stderr,
          "Usage: %s (--client|--server) --port N [options]\n"
          "  --host HOST       Peer/listen address (default: 127.0.0.1)\n"
          "  --cert FILE       PEM certificate chain\n"
          "  --key FILE        PEM private key\n"
          "  --ca FILE         PEM trust anchors (client verification)\n"
          "  --curves LIST     BoringSSL group list\n"
          "  --timeout SECS    Overall timeout (default: 20)\n",
          program);
}

bool ParseInt(const char *value, int *out) {
  char *end = nullptr;
  long parsed = strtol(value, &end, 10);
  if (*value == '\0' || *end != '\0' || parsed < 1 || parsed > 65535) {
    return false;
  }
  *out = static_cast<int>(parsed);
  return true;
}

bool ParseArgs(int argc, char **argv, Options *options) {
  for (int i = 1; i < argc; i++) {
    const std::string arg = argv[i];
    if (arg == "--client") {
      options->server = false;
    } else if (arg == "--server") {
      options->server = true;
    } else if (arg == "--host" || arg == "--port" || arg == "--cert" ||
               arg == "--key" || arg == "--ca" ||
               arg == "--curves" || arg == "--timeout") {
      if (++i == argc) {
        return false;
      }
      const char *value = argv[i];
      if (arg == "--host") options->host = value;
      if (arg == "--cert") options->cert = value;
      if (arg == "--key") options->key = value;
      if (arg == "--ca") options->ca = value;
      if (arg == "--curves") options->curves = value;
      if (arg == "--port" && !ParseInt(value, &options->port)) return false;
      if (arg == "--timeout" && !ParseInt(value, &options->timeout_seconds)) {
        return false;
      }
    } else {
      return false;
    }
  }
  return options->port != 0 &&
         (!options->server || (!options->cert.empty() && !options->key.empty()));
}

int MakeSocket(const Options &options) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) {
    perror("socket");
    return -1;
  }

  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(static_cast<uint16_t>(options.port));
  if (inet_pton(AF_INET, options.host.c_str(), &address.sin_addr) != 1) {
    fprintf(stderr, "Invalid IPv4 address: %s\n", options.host.c_str());
    close(fd);
    return -1;
  }

  if (options.server) {
    if (bind(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
      perror("bind");
      close(fd);
      return -1;
    }

    // A connected UDP socket gives the socket BIO the datagram boundaries and
    // fixed peer that DTLS expects. Peek at the ClientHello to learn the peer.
    pollfd descriptor{fd, POLLIN, 0};
    if (poll(&descriptor, 1, options.timeout_seconds * 1000) <= 0) {
      fprintf(stderr, "Timed out waiting for the first client datagram\n");
      close(fd);
      return -1;
    }

    sockaddr_in peer{};
    socklen_t peer_len = sizeof(peer);
    char byte;
    if (recvfrom(fd, &byte, sizeof(byte), MSG_PEEK, reinterpret_cast<sockaddr *>(&peer),
                 &peer_len) < 0 ||
        connect(fd, reinterpret_cast<sockaddr *>(&peer), peer_len) != 0) {
      perror("recvfrom/connect");
      close(fd);
      return -1;
    }
  } else if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
    perror("connect");
    close(fd);
    return -1;
  }

  if (fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK) != 0) {
    perror("fcntl");
    close(fd);
    return -1;
  }
  return fd;
}

bool WaitForSsl(SSL *ssl, int fd, int ssl_error,
                std::chrono::steady_clock::time_point deadline) {
  while (true) {
    auto now = std::chrono::steady_clock::now();
    if (now >= deadline) return false;

    int wait_ms = static_cast<int>(
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count());
    timeval dtls_timeout{};
    if (DTLSv1_get_timeout(ssl, &dtls_timeout)) {
      int dtls_ms = static_cast<int>(dtls_timeout.tv_sec * 1000 +
                                     dtls_timeout.tv_usec / 1000);
      if (dtls_ms < wait_ms) wait_ms = dtls_ms;
    }

    pollfd descriptor{fd, static_cast<short>(ssl_error == SSL_ERROR_WANT_WRITE
                                                 ? POLLOUT
                                                 : POLLIN),
                      0};
    int result = poll(&descriptor, 1, wait_ms);
    if (result < 0 && errno != EINTR) {
      perror("poll");
      return false;
    }
    if (result > 0) return true;
    if (DTLSv1_get_timeout(ssl, &dtls_timeout) && dtls_timeout.tv_sec == 0 &&
        dtls_timeout.tv_usec == 0 && DTLSv1_handle_timeout(ssl) < 0) {
      return false;
    }
  }
}

template <typename Operation>
int RunSslOperation(SSL *ssl, int fd,
                    std::chrono::steady_clock::time_point deadline,
                    Operation operation) {
  while (std::chrono::steady_clock::now() < deadline) {
    int result = operation();
    if (result > 0) return result;
    int error = SSL_get_error(ssl, result);
    if (error != SSL_ERROR_WANT_READ && error != SSL_ERROR_WANT_WRITE) {
      return result;
    }
    if (!WaitForSsl(ssl, fd, error, deadline)) return -1;
  }
  return -1;
}

}  // namespace

int main(int argc, char **argv) {
  Options options;
  if (!ParseArgs(argc, argv, &options)) {
    Usage(argv[0]);
    return 2;
  }

  SSL_CTX *ctx = SSL_CTX_new(DTLS_method());
  if (ctx == nullptr ||
      !SSL_CTX_set_min_proto_version(ctx, DTLS1_3_VERSION) ||
      !SSL_CTX_set_max_proto_version(ctx, DTLS1_3_VERSION)) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return 1;
  }

  if (!options.curves.empty() &&
      !SSL_CTX_set1_curves_list(ctx, options.curves.c_str())) {
    fprintf(stderr, "Unsupported group list: %s\n", options.curves.c_str());
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return 1;
  }
  if (!options.cert.empty() &&
      !SSL_CTX_use_certificate_chain_file(ctx, options.cert.c_str())) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return 1;
  }
  if (!options.key.empty() &&
      !SSL_CTX_use_PrivateKey_file(ctx, options.key.c_str(), SSL_FILETYPE_PEM)) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    return 1;
  }
  if (!options.ca.empty()) {
    if (!SSL_CTX_load_verify_locations(ctx, options.ca.c_str(), nullptr)) {
      ERR_print_errors_fp(stderr);
      SSL_CTX_free(ctx);
      return 1;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
  }

  int fd = MakeSocket(options);
  if (fd < 0) {
    SSL_CTX_free(ctx);
    return 1;
  }
  SSL *ssl = SSL_new(ctx);
  BIO *bio = BIO_new_socket(fd, BIO_CLOSE);
  if (ssl == nullptr || bio == nullptr) {
    ERR_print_errors_fp(stderr);
    if (bio == nullptr) close(fd);
    BIO_free(bio);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
  }
  SSL_set_bio(ssl, bio, bio);
  options.server ? SSL_set_accept_state(ssl) : SSL_set_connect_state(ssl);

  auto deadline = std::chrono::steady_clock::now() +
                  std::chrono::seconds(options.timeout_seconds);
  int result = RunSslOperation(ssl, fd, deadline,
                               [&] { return SSL_do_handshake(ssl); });
  if (result <= 0) {
    fprintf(stderr, "DTLS 1.3 handshake failed\n");
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return 1;
  }

  printf("HANDSHAKE_OK protocol=%s cipher=%s\n", SSL_get_version(ssl),
         SSL_CIPHER_standard_name(SSL_get_current_cipher(ssl)));
  fflush(stdout);

  char buffer[32];
  if (options.server) {
    result = RunSslOperation(ssl, fd, deadline,
                             [&] { return SSL_read(ssl, buffer, sizeof(buffer)); });
    if (result > 0) {
      int length = result;
      result = RunSslOperation(ssl, fd, deadline,
                               [&] { return SSL_write(ssl, buffer, length); });
    }
  } else {
    const char message[] = "dtls13-interop";
    result = RunSslOperation(ssl, fd, deadline,
                             [&] { return SSL_write(ssl, message, sizeof(message)); });
    if (result > 0) {
      result = RunSslOperation(ssl, fd, deadline,
                               [&] { return SSL_read(ssl, buffer, sizeof(buffer)); });
    }
  }

  if (result <= 0) {
    fprintf(stderr, "DTLS application-data exchange failed\n");
    ERR_print_errors_fp(stderr);
  } else {
    printf("APPLICATION_DATA_OK\n");
  }
  SSL_free(ssl);
  SSL_CTX_free(ctx);
  return result > 0 ? 0 : 1;
}
