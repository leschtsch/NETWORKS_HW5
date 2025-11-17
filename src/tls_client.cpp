#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <span>
#include <string>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "config.hpp"
#include "get_chunk_size.hpp"
#include "options.hpp"
#include "tls_send_receive.hpp"

namespace {

bool DoClient(SSL* ssl, std::size_t chunk_size, std::uint8_t xor_key) {
  std::string msg;
  if (!(std::cin >> msg)) {
    return false;
  }

  std::uint32_t msg_size = htonl(msg.size());
  std::span<std::uint8_t> msg_size_span{
      reinterpret_cast<std::uint8_t*>(&msg_size), sizeof(msg_size)};

  if (Send(ssl, chunk_size, msg_size_span) < sizeof(msg_size)) {
    std::cout
        << "Somethign badd happened to the server while receiving msg_size\n";
    std::exit(-1);
  }

  msg_size = ntohl(msg_size);
  std::span<std::uint8_t> msg_span{reinterpret_cast<std::uint8_t*>(msg.data()),
                                   msg_size};

  if (Send(ssl, chunk_size, msg_span) < msg_size) {
    std::cout << "Something badd happened to the server while receiving data\n";
    std::exit(-1);
  }

  std::vector<std::uint8_t> buff(msg_size);
  if (Receive(ssl, chunk_size, {buff.data(), msg_size}) < msg_size) {
    std::cout
        << "Something badd happened to the server while transmitting data\n";
    std::exit(-1);
  }

  for (ssize_t i = 0; i < msg_size; ++i) {
    if ((buff[i] ^ xor_key) != msg[i]) {
      std::cout << "incorrect encryption\n";
      break;
    }
  }

  return true;
}

int CreateSocket(const Options& options) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);

  if (sockfd < 0) {
    std::perror("socket");
    std::exit(-1);
  }

  struct sockaddr_in client_addr{};
  client_addr.sin_family = AF_INET;
  client_addr.sin_addr.s_addr = htons(INADDR_ANY);
  client_addr.sin_port = 0;

  struct timeval timeval;
  timeval.tv_sec = 5;
  timeval.tv_usec = 0;
  setsockopt(sockfd,
             SOL_SOCKET,
             SO_RCVTIMEO,
             reinterpret_cast<const char*>(&timeval),
             sizeof timeval);

  struct sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = options.addr;
  server_addr.sin_port = options.port;

  if (bind(sockfd,
           reinterpret_cast<const struct sockaddr*>(&client_addr),
           sizeof(client_addr)) < 0) {
    std::perror("bind");
    std::exit(-1);
  }

  if (connect(sockfd,
              reinterpret_cast<struct sockaddr*>(&server_addr),
              sizeof(server_addr)) < 0) {
    std::perror("connect");
    std::exit(-1);
  }

  return sockfd;
}

SSL_CTX* InitSsl(const Options& options) {
  std::cout << "initializing ssl context\n";

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();

  SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());

  std::string cert_file(options.cert_file);

  if (SSL_CTX_load_verify_file(ctx, cert_file.data()) != 1) {
    ERR_print_errors_fp(stderr);
    SSL_CTX_free(ctx);
    std::exit(-1);
  }

  return ctx;
}

SSL* ConnectSsl(SSL_CTX* ctx, int sockfd) {
  std::cout << "estabilishing ssl connection\n";

  SSL* ssl = SSL_new(ctx);
  if ((ssl == nullptr) || SSL_set_fd(ssl, sockfd) != 1) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    std::exit(-1);
  }

  if (SSL_connect(ssl) != 1) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    std::exit(-1);
  }
  std::cout << "estabilished\n";

  return ssl;
}

void DisconnectSsl(SSL* ssl) {
  std::cout << "cleaning up ssl connection\n";

  int res = SSL_shutdown(ssl);
  if (res == 2) {
    res = SSL_shutdown(ssl);
  }

  if (res != 1) {
    ERR_print_errors_fp(stderr);
    std::exit(-1);
  }

  SSL_free(ssl);
}

}  // namespace

int main(int argc, char* argv[]) {
  Options options;
  options.addr = kClientDefaultConnectAddr;
  options.port = kDefaultPort;
  options.xor_key = kDefaultXorKey;
  options.cert_file = kDefaultCertFile;
  ParseOprions(argc, std::span<char*>(argv, argc), options);

  SSL_CTX* ctx = InitSsl(options);
  int sockfd = CreateSocket(options);
  SSL* ssl = ConnectSsl(ctx, sockfd);

  std::size_t chunk_size = GetChunkSize(sockfd);

  while (DoClient(ssl, chunk_size, options.xor_key)) {}

  DisconnectSsl(ssl);
  SSL_CTX_free(ctx);
  close(sockfd);
}
