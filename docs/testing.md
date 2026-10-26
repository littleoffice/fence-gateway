# Testing

```
fenceverify   round trips, escaping edge cases, CDATA bodies, tampering, forgery,
              smuggled attributes, duplicate attributes, rotation, both schemes,
              staleness, malformed input
interop       16 vectors from the relay's unmodified fence.go: both layouts
              (1.0 prose preamble, 1.1 fenced preamble) × escaped and CDATA
              bodies, plus tampering of each
gateway       end-to-end over HTTP: pass, block, annotate, rotation recovery,
              pin enforcement, signature stripping; the interop vectors run
              through the policy
```

Run them with `go test -race ./...`, as CI does.

## Interop vectors

The interop tests matter more than their size suggests: everything else verifies against
this package's own generator, which would hide any bug symmetric across both sides. The
vectors live in `interop/testdata/relay` and come from the relay commit pinned in
`RELAY_COMMIT` there. `interop/regen.sh` rebuilds them, and CI rebuilds them into a
scratch directory on every run and tests the fresh output too. To move to a newer relay,
change the pin, run the script, and commit the result.
