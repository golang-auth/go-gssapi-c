#include "gss.h"

int has_channel_bound() {
#if defined(GSS_C_CHANNEL_BOUND_FLAG)
	return 1;
#else
	return 0;
#endif
}