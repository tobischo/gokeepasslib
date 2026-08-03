# argon2

This package is a fork off the https://pkg.go.dev/golang.org/x/crypto/argon2 package.
It is generally recommended to use the officially supported package rather than this one.
The only reason this fork exists is because keepass selected argon2 in `2d` mode,
which was chosen not to be exposed in the implementation. In order to be able
to implement a compatible version for keepass.
Read up [here](https://github.com/golang/go/issues/23602) about more details as to why it was not exposed.

## Keeping the fork up to date

Every file except `argon2d.go` is a verbatim copy of the upstream package, so
they should never be edited by hand. Instead:

```sh
make diff-upstream            # show how the copies differ from the latest upstream
make update                   # copy the newest upstream sources in, tidy and test
make update UPSTREAM_VERSION=v0.54.0   # or pin a specific version
```

`make update` also warns when upstream gains a file that is not yet tracked in
`UPSTREAM_FILES`, and fails when a tracked file disappears upstream.
