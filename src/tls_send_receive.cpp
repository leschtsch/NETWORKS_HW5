#include "tls_send_receive.hpp"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <span>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

std::size_t Send(SSL* ssl,
                 std::size_t chunk_size,
                 std::span<std::uint8_t> msg) {
  std::cout << "sending " << msg.size() << " bytes\n";

  std::size_t already_sent = 0;

  while (already_sent < msg.size()) {
    std::size_t need_send = std::min(msg.size() - already_sent, chunk_size);

    std::cout << "already sent: " << already_sent << " need send: " << need_send
              << "\n";

    ssize_t sent_this_iter =
        SSL_write(ssl, msg.data() + already_sent, static_cast<int>(need_send));

    if (sent_this_iter < 0) {
      ERR_print_errors_fp(stderr);
      break;
    }

    already_sent += sent_this_iter;

    std::cout << "already_sent: " << already_sent
              << " sent_this_iter: " << sent_this_iter << "\n";
  }

  return already_sent;
}

std::size_t Receive(SSL* ssl,
                    std::size_t chunk_size,
                    std::span<std::uint8_t> msg) {
  std::size_t already_received = 0;

  std::cout << "receiving " << msg.size() << " bytes\n";

  while (already_received < msg.size()) {
    std::size_t need_receive =
        std::min(msg.size() - already_received, chunk_size);
    std::cout << "already received: " << already_received
              << " need receive: " << need_receive << "\n";

    ssize_t received_this_iter = SSL_read(
        ssl, msg.data() + already_received, static_cast<int>(need_receive));

    if (received_this_iter < 0) {
      ERR_print_errors_fp(stderr);
      break;
    }

    if (received_this_iter == 0) {
      std::cout << "client left\n";
      break;
    }

    already_received += received_this_iter;

    std::cout << "already received: " << already_received
              << " received_this_iter: " << received_this_iter << "\n";
  }

  return already_received;
}
