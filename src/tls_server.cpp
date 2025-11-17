#include <arpa/inet.h>
#include <cerrno>
#include <cstdlib>
#include <iostream>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <span>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

#include "config.hpp"
#include "get_chunk_size.hpp"
#include "options.hpp"
#include "tls_send_receive.hpp"

namespace {

bool ServerOneMsg(SSL* ssl, std::size_t chunk_size, std::uint8_t xor_key) {
  std::uint32_t msg_size = 0;
  std::span<uint8_t> msg_size_span{reinterpret_cast<uint8_t*>(&msg_size),
                                   sizeof(msg_size)};
  if (Receive(ssl, chunk_size, msg_size_span) < sizeof(msg_size)) {
    std::cout << "client left?\n";
    return false;
  }

  msg_size = ntohl(msg_size);

  static std::vector<std::uint8_t> buff;
  buff.clear();
  buff.resize(msg_size);

  if (Receive(ssl, chunk_size, {buff.data(), msg_size}) < msg_size) {
    std::cout
        << "something bad happened to the client while transmitting data(\n";
    return false;
  }

  for (ssize_t i = 0; i < msg_size; ++i) {
    buff[i] ^= xor_key;
  }

  std::size_t sent = Send(ssl, chunk_size, {buff.data(), msg_size});

  if (sent < msg_size) {
    std::cout << "something bad happened to the client while receiving data(\n";
    return false;
  }

  return true;
}

SSL* ConnectSsl(SSL_CTX* ctx, int sockfd) {
  std::cout << "estabilishing ssl connection\n";

  SSL* ssl = SSL_new(ctx);
  if ((ssl == nullptr) || SSL_set_fd(ssl, sockfd) != 1) {
    ERR_print_errors_fp(stderr);
    SSL_free(ssl);
    std::exit(-1);
  }
  
  if (SSL_accept(ssl) != 1) {
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
  }

  SSL_free(ssl);
}

void DoServer(SSL_CTX* ctx, int sockfd, std::uint8_t xor_key) {
  std::size_t chunk_size = GetChunkSize(sockfd);

  SSL* ssl = ConnectSsl(ctx, sockfd);

  while (ServerOneMsg(ssl, chunk_size, xor_key)) {}

  DisconnectSsl(ssl);

  if (close(sockfd) < 0) {
    std::perror("close");
    std::exit(-1);
  }
}

int CreateListenSocket(const Options& options) {
  int listenfd = socket(AF_INET, SOCK_STREAM, 0);
  if (listenfd < 0) {
    std::perror("socket");
    std::exit(-1);
  }

  int flag = 1;
  int status =
      setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));
  if (status < 0) {
    std::perror("setsockopt");
    std::exit(-1);
  }

  struct sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = options.addr;
  server_addr.sin_port = options.port;

  if (bind(listenfd,
           reinterpret_cast<const struct sockaddr*>(&server_addr),
           sizeof(server_addr)) < 0) {
    std::perror("bind");
    std::exit(-1);
  }

  if (listen(listenfd, 1) < 0) {
    std::perror("listen");
    std::exit(-1);
  }

  std::cout << "listening on " << inet_ntoa({options.addr}) << ":"
            << ntohs(options.port) << " with xor_key "
            << static_cast<int>(options.xor_key) << "\n";

  return listenfd;
}

SSL_CTX* InitSsl(const Options& options) {
  std::cout << "initializing ssl context\n";

  SSL_library_init();
  OpenSSL_add_all_algorithms();
  SSL_load_error_strings();
  SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());

  if (SSL_CTX_set_ecdh_auto(ctx, 1) != 1) {
    ERR_print_errors_fp(stderr);
    std::exit(-1);
  }

  std::string key_file(options.key_file);
  std::string cert_file(options.cert_file);

  if (SSL_CTX_use_certificate_file(ctx, cert_file.data(), SSL_FILETYPE_PEM) !=
      1) {
    ERR_print_errors_fp(stderr);
    std::exit(-1);
  }

  if (SSL_CTX_use_PrivateKey_file(ctx, key_file.data(), SSL_FILETYPE_PEM) !=
      1) {
    ERR_print_errors_fp(stderr);
    std::exit(-1);
  }

  return ctx;
}

}  // namespace

int main(int argc, char* argv[]) {
  Options options;
  options.addr = kServerDefaultListenAddr;
  options.port = kDefaultPort;
  options.xor_key = kDefaultXorKey;
  options.cert_file = kDefaultCertFile;
  options.key_file = kDefaultKeyFile;
  ParseOprions(argc, std::span<char*>(argv, argc), options);

  SSL_CTX* ctx = InitSsl(options);

  int listenfd = CreateListenSocket(options);

  while (int clientfd = accept(listenfd, nullptr, nullptr)) {
    std::cout << "new client\n";
    DoServer(ctx, clientfd, options.xor_key);
  }

  SSL_CTX_free(ctx);
  close(listenfd);
}
