#ifndef GUARD_MINIFILTER_H
#define GUARD_MINIFILTER_H

#define TEST 1

typedef enum {
	CONNECTION_CLOSED = 0,
	CONNECTION_UNAUTHENTICATED,
	CONNECTION_AUTHENTICATING,
	CONNECTION_AUTHENTICATED,
	CONNECTION_CONNECTED
} CONNECTION_STATE;

#endif //GUARD_MINIFILTER_H