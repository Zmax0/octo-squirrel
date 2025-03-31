# Benchmark

```shell
cargo bench -p octo-squirrel-test
```

## Debug Output

```shell
CRITERION_DEBUG=1 cargo bench -p octo-squirrel-test
```

# Tools

## HTTP server

```shell
cargo run -p octo-squirrel-test --bin http_server -- ${listening address}
```

## Tracing client/server

```shell
# Run tracing client
cargo run -p octo-squirrel-test --bin tracing_client  -- ${config file path}
# Run tokio-console in another terminal
tokio-console

# Run tracing server
cargo run -p octo-squirrel-test --bin tracing_server  -- ${config file path}
# Run tokio-console in another terminal
tokio-console http://127.0.0.1:6670
```

