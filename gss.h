#if defined(OSX_HAS_GSS_FRAMEWORK)
#include <GSS/gssapi.h>
#define IS_HEIMDAL 1

#else
#include <stddef.h>
#include <stdlib.h>
#include <gssapi/gssapi.h>

// Heimdal has defined HEIMDAL_DEPRECATED since 2010.  We use the presence
// of this to detect whether Heimdal is in use.  Note this could break in
// the future if the developers change the visibility of this define.
// FreeBSD defines GSSAPI_DEPRECATED_FUNCTION
#if defined(HEIMDAL_DEPRECATED) || defined(GSSAPI_DEPRECATED_FUNCTION)
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

#endif

#if ! defined(GSS_C_NO_BUFFER_SET)
typedef struct gss_buffer_set_desc_struct {
    size_t count;
    gss_buffer_desc *elements;
} gss_buffer_set_desc, *gss_buffer_set_t;

#define GSS_C_NO_BUFFER_SET ((gss_buffer_set_t) 0)
#endif

extern gss_buffer_desc gss_empty_buffer;
extern int has_channel_bound();
extern int is_mac_framework();


