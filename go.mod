module github.com/golang-auth/go-gssapi-c

go 1.18

require (
	github.com/golang-auth/go-gssapi/v3 v3.0.0-alpha.2
	github.com/stretchr/testify v1.9.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/golang-auth/go-gssapi/v3 => ../go-gssapi/v3
