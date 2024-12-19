#include <gssapi.h>

// Heimdal has defined HEIMDAL_DEPRECATED since 2010.  We use the presence
// of this to detect whether Heimdal is in use.  Note this could break in
// the future if the developers change the visibility of this define.
//
#if defined(HEIMDAL_DEPRECATED) ||  defined(GSSKRB_APPLE_DEPRECATED)
    #define IS_HEIMDAL 1
#else
    #define IS_HEIMDAL 0
#endif

// Assume for now that if its not Heimdal then it must be MIT..
// this means that Openvision/Cybersafe etc will probably not work
// If anyone is using other GSSAPI libraries then we can add
// checks for those here..
#if IS_HEIMDAL == 0
// load MIT extensions if not on Heimdal
#include <gssapi/gssapi_ext.h>
#endif

int has_channel_bound();

extern gss_buffer_desc gss_empty_buffer;