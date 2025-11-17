#ifndef CONFIG_H
#define CONFIG_H

#include <arpa/inet.h>

static const in_port_t kDefaultPort = htons(8080);

static const in_addr_t kServerDefaultListenAddr = htonl(INADDR_ANY);
static const in_addr_t kClientDefaultConnectAddr = inet_addr("127.0.0.1");

static constexpr char kDefaultXorKey = 0;

static constexpr int kMaxChunkSize = 1LLU << 16LLU;

//===========================V=TLS=PART=V===========================================================

// Trusted root certificate
static constexpr const char* kDefaultCertFile = "cert.pem";
static constexpr const char* kDefaultKeyFile = "key.pem";

static constexpr int kMinChunkSize = 128;
static constexpr int kPossibleTlsOverhead = 128; // Idk, should be enough
#endif  // CONFIG_H
