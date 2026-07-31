/*
 * Benchmark TCP echo server derived from uSockets' examples/echo_server.c at
 * 2353808c2e605c4f38bd9f09261fff13ae2a58be.
 *
 * This intentionally uses the upstream library's normal Linux backend and
 * socket defaults. TLS, per-message logging, and per-message idle timer
 * updates are disabled so the benchmark measures the transport loop itself.
 */

#include <libusockets.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SSL 0

struct echo_socket {
	char *backpressure;
	int length;
};

struct echo_context {
	int unused;
};

static void on_wakeup(struct us_loop_t *loop) {
	(void) loop;
}

static void on_pre(struct us_loop_t *loop) {
	(void) loop;
}

static void on_post(struct us_loop_t *loop) {
	(void) loop;
}

static struct us_socket_t *on_echo_socket_writable(struct us_socket_t *s) {
	struct echo_socket *es = (struct echo_socket *) us_socket_ext(SSL, s);
	int written = us_socket_write(SSL, s, es->backpressure, es->length, 0);

	if (written < 0) {
		written = 0;
	}

	if (written < es->length) {
		int remaining = es->length - written;
		memmove(es->backpressure, es->backpressure + written, (size_t) remaining);
		es->length = remaining;
	} else {
		free(es->backpressure);
		es->backpressure = NULL;
		es->length = 0;
	}

	return s;
}

static struct us_socket_t *on_echo_socket_close(
	struct us_socket_t *s,
	int code,
	void *reason
) {
	struct echo_socket *es = (struct echo_socket *) us_socket_ext(SSL, s);

	(void) code;
	(void) reason;
	free(es->backpressure);
	es->backpressure = NULL;
	es->length = 0;

	return s;
}

static struct us_socket_t *on_echo_socket_end(struct us_socket_t *s) {
	us_socket_shutdown(SSL, s);
	return us_socket_close(SSL, s, 0, NULL);
}

static struct us_socket_t *on_echo_socket_data(
	struct us_socket_t *s,
	char *data,
	int length
) {
	struct echo_socket *es = (struct echo_socket *) us_socket_ext(SSL, s);
	int written = us_socket_write(SSL, s, data, length, 0);

	if (written < 0) {
		written = 0;
	}

	if (written < length) {
		int remaining = length - written;
		size_t buffered = (size_t) es->length;
		char *new_buffer = (char *) realloc(
			es->backpressure,
			buffered + (size_t) remaining
		);

		if (new_buffer == NULL) {
			return us_socket_close(SSL, s, 0, NULL);
		}

		memcpy(new_buffer + buffered, data + written, (size_t) remaining);
		es->backpressure = new_buffer;
		es->length += remaining;
	}

	return s;
}

static struct us_socket_t *on_echo_socket_open(
	struct us_socket_t *s,
	int is_client,
	char *ip,
	int ip_length
) {
	struct echo_socket *es = (struct echo_socket *) us_socket_ext(SSL, s);

	(void) is_client;
	(void) ip;
	(void) ip_length;
	es->backpressure = NULL;
	es->length = 0;

	return s;
}

int main(int argc, char **argv) {
	int port = argc > 1 ? atoi(argv[1]) : 9301;
	const char *host = argc > 2 ? argv[2] : "127.0.0.1";
	struct us_loop_t *loop;
	struct us_socket_context_options_t options = {0};
	struct us_socket_context_t *echo_context;
	struct us_listen_socket_t *listen_socket;

	if (port < 1 || port > 65535) {
		fprintf(stderr, "invalid port: %d\n", port);
		return 2;
	}

	loop = us_create_loop(0, on_wakeup, on_pre, on_post, 0);
	if (loop == NULL) {
		fputs("failed to create uSockets loop\n", stderr);
		return 1;
	}

	echo_context = us_create_socket_context(
		SSL,
		loop,
		sizeof(struct echo_context),
		options
	);
	if (echo_context == NULL) {
		fputs("failed to create uSockets context\n", stderr);
		us_loop_free(loop);
		return 1;
	}

	us_socket_context_on_open(SSL, echo_context, on_echo_socket_open);
	us_socket_context_on_data(SSL, echo_context, on_echo_socket_data);
	us_socket_context_on_writable(SSL, echo_context, on_echo_socket_writable);
	us_socket_context_on_close(SSL, echo_context, on_echo_socket_close);
	us_socket_context_on_end(SSL, echo_context, on_echo_socket_end);

	listen_socket = us_socket_context_listen(
		SSL,
		echo_context,
		host,
		port,
		LIBUS_LISTEN_DEFAULT,
		sizeof(struct echo_socket)
	);
	if (listen_socket == NULL) {
		fprintf(stderr, "failed to listen on %s:%d\n", host, port);
		us_socket_context_free(SSL, echo_context);
		us_loop_free(loop);
		return 1;
	}

	printf("uSockets echo listening on %s:%d\n", host, port);
	fflush(stdout);
	us_loop_run(loop);

	us_listen_socket_close(SSL, listen_socket);
	us_socket_context_free(SSL, echo_context);
	us_loop_free(loop);
	return 0;
}
