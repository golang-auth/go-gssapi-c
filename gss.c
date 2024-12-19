#include "gss.h"

int has_channel_bound() {
#if defined(GSS_C_CHANNEL_BOUND_FLAG)
	return 1;
#else
	return 0;
#endif
}

 gss_buffer_desc gss_empty_buffer = GSS_C_EMPTY_BUFFER;
 