# argon2

This package is a fork off the https://pkg.go.dev/golang.org/x/crypto/argon2 package.
It is generally recommended to use the officially supported package rather than this one.
The only reason this fork exists is because keepass selected argon2 in `2d` mode,
which was chosen not to be exposed in the implementation. In order to be able
to implement a compatible version for keepass.
Read up [here](https://github.com/golang/go/issues/23602) about more details as to why it was not exposed.
