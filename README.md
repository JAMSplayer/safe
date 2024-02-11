# Simple SAFE Network API

* [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html)
* Arguments and return types (including errors – E in Result<T, E> [C-GOOD-ERR](https://rust-lang.github.io/api-guidelines/interoperability.html#c-good-err)):
** Primitives and simple structs wherever possible
** Derived traits: Deserialize, Serialize, Debug ([C-SERDE](https://rust-lang.github.io/api-guidelines/interoperability.html#c-serde), [C-COMMON-TRAITS](https://rust-lang.github.io/api-guidelines/interoperability.html#c-common-traits), [C-DEBUG](https://rust-lang.github.io/api-guidelines/debuggability.html#c-debug))
** Heap-allocated types, where possible: String instead of &str, Vec<u8> instead of &[u8] etc.
** No need to depend on external crates. Re-export identifiers when neeeded (`pub use`).
** Don't write to stdout/stderr, just return `Result` or use logging infrastructure.
