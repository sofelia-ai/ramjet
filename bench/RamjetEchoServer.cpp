/* WebSocket echo server for the shootout, based on uWebSockets'
 * examples/EchoServer.cpp. Changes from upstream:
 *  - no SSL (built without WITH_OPENSSL/WITH_BORINGSSL; uWS::App() is
 *    the plain non-TLS listener, so the key/cert/passphrase options are
 *    dropped entirely rather than left in as dead SSL config)
 *  - compression explicitly DISABLED (upstream example turns compression
 *    ON via DEDICATED_COMPRESSOR|DEDICATED_DECOMPRESSOR; we want raw
 *    framing only, matching that our own server doesn't offer
 *    permessage-deflate either). Built with -DUWS_NO_ZLIB, so
 *    permessage-deflate isn't even compiled in, not just runtime-disabled.
 *  - sendPingsAutomatically = false, so this server behaves like the
 *    other three in the shootout (none of which proactively ping) —
 *    inbound pings are still auto-ponged by uWS itself either way
 *  - port taken from argv[1] instead of hardcoded 9001
 *  - single-threaded: one uWS::App().run() on the main thread, same as
 *    upstream's EchoServer.cpp (EchoServerThreaded.cpp is the multi-
 *    threaded variant, deliberately not used here)
 */
#include "App.h"
#include <cstdlib>
#include <iostream>

int main(int argc, char **argv) {
    int port = 9401;
    if (argc > 1) {
        port = std::atoi(argv[1]);
    }

    struct PerSocketData {
        /* No per-connection state needed for a plain echo. */
    };

    uWS::App().ws<PerSocketData>("/*", {
        /* Settings */
        .compression = uWS::CompressOptions(uWS::DISABLED),
        .maxPayloadLength = 100 * 1024 * 1024,
        .idleTimeout = 16,
        .maxBackpressure = 100 * 1024 * 1024,
        .closeOnBackpressureLimit = false,
        .resetIdleTimeoutOnSend = false,
        .sendPingsAutomatically = false,
        /* Handlers */
        .upgrade = nullptr,
        .open = [](auto */*ws*/) {},
        .message = [](auto *ws, std::string_view message, uWS::OpCode opCode) {
            /* Echo verbatim: same bytes, same opcode (TEXT or BINARY), no
             * compression. */
            ws->send(message, opCode, false);
        },
        .dropped = [](auto */*ws*/, std::string_view /*message*/, uWS::OpCode /*opCode*/) {},
        .drain = [](auto */*ws*/) {},
        .ping = [](auto */*ws*/, std::string_view) {},
        .pong = [](auto */*ws*/, std::string_view) {},
        .close = [](auto */*ws*/, int /*code*/, std::string_view /*message*/) {}
    }).listen(port, [port](auto *listen_socket) {
        if (listen_socket) {
            std::cout << "listening on " << port << std::endl;
        } else {
            std::cerr << "failed to listen on " << port << std::endl;
            std::exit(1);
        }
    }).run();
}
