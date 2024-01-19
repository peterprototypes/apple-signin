Apple Sign In for Rust
=======================

[![Crates.io](https://img.shields.io/crates/v/apple-signin?color=4d76ae)](https://crates.io/crates/apple-signin)
[![Docs](https://docs.rs/apple-signin/badge.svg)](https://docs.rs/apple-signin)

This crate provides an API to verify and decode Apple's identity JWT, typically generated via the `AuthenticationServices` iOS Framework.

## Usage

Add `apple-signin` to your project.

```bash
cargo add apple-signin
```
or
```toml
[dependencies]
apple-signin = "*"
```

And then, you can verify an `identityToken` obtained from [ASAuthorizationAppleIDCredential](https://developer.apple.com/documentation/authenticationservices/asauthorizationappleidcredential)

```rust
use apple_signin::AppleJwtClient;

#[tokio::main]
async fn main() -> Result<()> {
    let mut client = AppleJwtClient::new(&["com.example.myapp"]);
    let payload = client.decode("[IDENTITY TOKEN]").await?;

    dbg!(payload);

    Ok(())
}
```

For more detailed instructions, check out the [documentation](https://docs.rs/apple-signin).

## License
 * MIT license ([LICENSE-MIT](docs/LICENSE-MIT) or http://opensource.org/licenses/MIT)
at your option.