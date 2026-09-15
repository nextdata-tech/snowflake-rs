# snowflake-jwt

Generates JWT token in Snowflake-compatible format, see [Using Key Pair Authentication](https://docs.snowflake.com/en/developer-guide/sql-api/authenticating#label-sql-api-authenticating-key-pair).

Can be used in order to run queries against [SQL REST API](https://docs.snowflake.com/developer-guide/sql-api/intro).

## Usage

```toml
[dependencies]
snowflake-jwt = { version = "0.4", features = ["rust_crypto"] }
```

### Crypto backend

Signing is delegated to [`jsonwebtoken`](https://crates.io/crates/jsonwebtoken), which needs exactly
one crypto backend. There is no default, so every build picks one explicitly:

- `rust_crypto` — pure Rust, so it cross-compiles without a C toolchain.
- `aws_lc_rs` — signs with [`aws-lc-rs`](https://crates.io/crates/aws-lc-rs).

```toml
[dependencies]
snowflake-jwt = { version = "0.4", features = ["aws_lc_rs"] }
```

Enabling neither is a compile error. Enabling both is not: Cargo features are additive, so two
crates in one dependency graph can pick different backends, and `aws_lc_rs` wins that tie.

Check [examples](./examples) for working programs using the library.

```rust
use anyhow::Result;
use std::fs;
use snowflake_jwt;

fn get_token(private_key_path: &str, account_identifier: &str, username: &str) -> Result<String> {
    let pem = fs::read_to_string(private_key_path)?;
    let full_identifier = format!("{}.{}", account_identifier, username);
    let jwt = snowflake_jwt::generate_jwt_token(&pem, &full_identifier)?;

    Ok(jwt)
}
```
