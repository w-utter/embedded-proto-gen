Parses Protobuf (.proto) files and generates bindings using Rust. 
The primary purpose of this crate is to be able to generate them for an embedded environment, but it can be used wherever seen fit.

Currently the supported languages are:
    - C++ (C++23)

Note: Any message which specifies a map<K, V> in one of their fields will not work as this crate does not currently support them.
