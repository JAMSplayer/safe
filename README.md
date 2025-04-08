# Simple SAFE Network API

The goal is to create a high-level Safenet API, that follows best practices and avoids unnecessary complexities. It uses sane defaults, and doesn't need unnecessary additional dependencies – it has "batteries included".

* [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html), except:
* Arguments and return types (including errors – E in Result<T, E> [C-GOOD-ERR](https://rust-lang.github.io/api-guidelines/interoperability.html#c-good-err)):
** Primitives and simple structs wherever possible
** Derived traits: Deserialize, Serialize, Debug ([C-SERDE](https://rust-lang.github.io/api-guidelines/interoperability.html#c-serde), [C-COMMON-TRAITS](https://rust-lang.github.io/api-guidelines/interoperability.html#c-common-traits), [C-DEBUG](https://rust-lang.github.io/api-guidelines/debuggability.html#c-debug))
** No need to depend on external crates. Re-export identifiers when neeeded (`pub use`).
** (TODO) Don't write to stdout/stderr, just return `Result` or use logging infrastructure.

## Testing

`cargo test`
