# Simple SAFE Network API

The goal is to create a high-level Safenet API, that follows best practices and hides unnecessary complexities. It is created top-down, with Application Developers in mind. 

* [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html), except:
** C-DOCS: It's too early, wait for upstream API stabilization. There are examples and tests, that document the library well enough.
* Arguments and return types (including errors – E in Result<T, E> [C-GOOD-ERR](https://rust-lang.github.io/api-guidelines/interoperability.html#c-good-err)):
** Primitives and simple structs wherever possible
** Derived traits: Deserialize, Serialize, Debug ([C-SERDE](https://rust-lang.github.io/api-guidelines/interoperability.html#c-serde), [C-COMMON-TRAITS](https://rust-lang.github.io/api-guidelines/interoperability.html#c-common-traits), [C-DEBUG](https://rust-lang.github.io/api-guidelines/debuggability.html#c-debug))
** Heap-allocated types, where possible: String instead of &str, Vec<u8> instead of &[u8] etc. This will make interfacing from other languages easier.
** No need to depend on external crates. Re-export identifiers when neeeded (`pub use`).
** Don't write to stdout/stderr, just return `Result` or use logging infrastructure.

## Testing

`cargo test`

## Building

If you want to connect to testnet, you have to set `NETWORK_VERSION_MODE` environment variable to name of testnet's *safe_network* repo release branch before build, for example:

```
export NETWORK_VERSION_MODE="alpha-reward-test"
```
