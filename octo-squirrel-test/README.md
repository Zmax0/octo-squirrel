# Benchmark

```shell
cargo bench -p octo-squirrel-test
```

## Debug Output

```shell
CRITERION_DEBUG=1 cargo bench -p octo-squirrel-test
```

# Run

## Test http server

```shell
cargo run -p octo-squirrel-test --bin http_server 127.0.0.1:16802
```