//go:build freebsd

// SPDX-License-Identifier: Apache-2.0

package gssapi

//#cgo !usepkgconfig CFLAGS: -I/usr/include
//#cgo !usepkgconfig LDFLAGS: -L/usr/lib -lgssapi -lgssapi_krb5 -lheimntlm -lkrb5 -lhx509 -lcom_err -lcrypto -lasn1 -lwind -lheimbase -lroken -lcrypt -pthread
//#cgo usepkgconfig pkg-config:krb5-gssapi,krb5
import "C"
