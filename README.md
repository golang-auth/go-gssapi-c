# Go-GSSAPI C bindings provider

The go-gssapi-c package is a provider that implements the (Go GSSAPI)[golang-auth/go-gssapi/v3] interfaces for access to a C library implementing RFC 2744.
The provider has been tested with the following OS/GSSAPI library combinations:
 * Linux
    * MIT Kerberos
    * Heimdal Kerberos 7.8.0
 * MacOS
    * Apple Kerberos
    * MIT Kerberos (from Homebrew)
    * Heimdal Kerberos 7.8.0 (from Homebrew)
 * FreeBSD
    * FreeBSD Kerberos Kerberos (from ports)
    * Heimdal Kerberos 7.8.0 (from ports)
 * OpenBSD with Heimdal Kerberos 7.8.0 from ports

The provider aims to provide a consistent experience across the implementations by working around some quirks and bugs.


## Using the provider

No application code should call go-gssapi-c directly.  Rather, consumers of the GSSAPI API should make use of
the Provider interface from go-gssapi/v3 to instantiate an instance of the provider by name.  The provider registers itself using the identifier
`github.com/golang-auth/go-gssapi-c`.  This name shold be passed to the `NewProvider` or `MustNewProvider` functions from go-gssapi/v3.

The go-gssapi-c package should be linked to the resultant executable by importing it silently somewhere in the application code:

```go
  import _ "github.com/golang-auth/go-gssapi-c"
```

Most of the tested operating systems can support multiple GSSAPI libraries.  Build tags and enviornment variables can be used to influence
the choice of GSSAPI library that the Go compiler will link to.

### Linux

The Go compiler will use `pkg-config` to configure the library settings.  Make sure that the environment variable `PKG_CONFIG_PATH` points to the pkgconf
files installed by the GSSAPI implementation you wish to use (see below).

### MacOS

MacOS ships with Apple Kerberos which was forked from Heimal a long time ago.  This base implementation will be used by default.  A more modern
Heimdal or MIT Kerberos can be installed using Homebrew and Go can link against that version if the `PKG_COFNIG_PATH` enviornment variable is set
and the `usepkgconfig` built tag is supplied.

### FreeBSD

FreeBSD ships with a version of Heimdal that was forked a long time ago.  As with MacOS, this base implementation will be used by default.
The ports tree can be used to install a more modern Heimdal version or MIT Kerberos and that version can be use by this provider by
supplying the `usepkgconf` build tag.  Note that it is not possible to support both MIT Kerberos and Heimdal from ports simultaneously.

### OpenBSD

Heimdal 7.8 can be installed from the OpenBSD ports sytem and that version will be used by the provider.


| Operating system | GSSAPI implementation  | Pre-requisite packages | `PKG_CONFIG_PATH` | Build tags |
| ---------------  | ---------------------- | ---------------------- | ----------------- | ---------- |
| Ubuntu           | MIT                    | krb5-user, libkrb5-devel, pkg-config |  n/a   | n/a     |
| Ubuntu           | Heimdal                | heimdal-dev, pkg-config | n/a              | n/a        |
| MacOS            | Apple Kerberos         | n/a                     | n/a              | n/a        |
| MacOS            | MIT                    | krb5                    | `/opt/homebrew/opt/krb5/lib/pkgconfig` | `usepkgconfig` |
| MacOS            | Heimdal 7.8            | heimdal                 | `/opt/homebrew/opt/heimdal/lib/pkgconfig` | `usepkgconfig` |
| FreeBSD          | FreeBSD Kerberos       | n/a                     | n/a				 | n/a        |
| FreeBSD          | MIT                    | krb5, pkgconf           | n/a 			 | `usepkgconfig`       |
| FreeBSD          | Heimdal 7.8            | heimdal, pkgconf        | n/a 			 | `usepkgconfig`        |
| OpenBSD          | Heimdal 7.8            | heimdal                 | n/a              | n/a        |

Note that FreeBSD and Ubuntu cannot sanely support having MIT and Heimdal Kerbero installed at the same time as
both packages try to own the same pkg-config `.pc` files.

