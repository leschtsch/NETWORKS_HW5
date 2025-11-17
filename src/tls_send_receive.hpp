#ifndef TLS_SEND_RECEIVE
#define TLS_SEND_RECEIVE

#include <cstddef>
#include <cstdint>
#include <openssl/ssl.h>
#include <span>

std::size_t Send(SSL* ssl,
                 std::size_t chunk_size,
                 std::span<std::uint8_t> msg);
std::size_t Receive(SSL* ssl,
                    std::size_t chunk_size,
                    std::span<std::uint8_t> msg);

#endif  // TLS_SEND_RECEIVE
