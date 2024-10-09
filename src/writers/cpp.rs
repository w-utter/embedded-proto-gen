use protobuf::reflect::{FileDescriptor, EnumDescriptor, MessageDescriptor, ServiceDescriptor, OneofDescriptor, FieldDescriptor};
use protobuf::reflect::RuntimeType;

use crate::CollectionDependencies as CollectionDeps;
use crate::ProtobufType;

#[derive(Default)]
pub struct CppWriter {
    inner: Vec<u8>,
    tab_indent: usize,
    options: CppWriterOptions,
}

#[derive(Default)]
pub struct CppWriterOptions {
    pub include_main: bool,
    pub reflection_tests: Option<ReflectionTests>, //per struct
    pub generate_fuzz: Option<FuzzTests>, //per struct
}

#[derive(Default)]
pub struct ReflectionTests {
    pub tests_per_struct: u64,
    pub buffer_size: usize,
    pub max_len: usize,
}

#[derive(Default)]
pub struct FuzzTests {
    pub tests_per_struct: u64,
    pub buffer_size: usize,
}

impl AsRef<[u8]> for CppWriter {
    fn as_ref(&self) -> &[u8] {
        self.inner.as_ref()
    }
}

use protobuf::descriptor::field_descriptor_proto::Type;
use protobuf::reflect::ReflectValueRef;
use protobuf::reflect::RuntimeFieldType;

impl CppWriter {
    pub fn new() -> Self {
        Self::default()
    }

    fn increment_tab(&mut self) {
        self.tab_indent += 1;
    }

    fn decrement_tab(&mut self) {
        self.tab_indent -= 1;
    }

    fn tab(&self) -> String {
        "\t".repeat(self.tab_indent)
    }

    fn writeln(&mut self, f: impl FnOnce(&mut Self) -> std::io::Result<()>) -> std::io::Result<()> {
        let tab = self.tab();
        write!(self, "{tab}")?;
        f(self)?;
        self.newline()?;
        Ok(())
    }

    fn newline(&mut self) -> std::io::Result<()> {
        write!(self, "\n")
    }

    fn scoped(&mut self, begin: impl FnOnce(&mut Self) -> std::io::Result<()>, scope: impl FnOnce(&mut Self) -> std::io::Result<()>, close: impl FnOnce(&mut Self) -> std::io::Result<()>) -> std::io::Result<()> {
        begin(self)?;
        self.increment_tab();
        scope(self)?;
        self.decrement_tab();
        close(self)?;
        Ok(())
    }

    fn write_union(&mut self, oneof: &OneofDescriptor, collection_deps: &CollectionDeps) -> std::io::Result<()> {
        let bit_size = (oneof.fields().count() + 1).next_power_of_two().ilog2();
        let union_name = oneof.name();
        self.scoped(
            |w| w.writeln(|w| write!(w, "typedef union {union_name}_storage_t {{")),
            |w| {
                w.writeln(|w| write!(w, "bool dummy {{false}};"))?;
                for variant in oneof.fields() {
                    let deps = collection_deps.from_field_num(&variant.number());
                    w.write_field(&variant, deps, true)?;
                }
                w.writeln(|w| write!(w, "constexpr {union_name}_storage_t() {{}}"))?;
                w.writeln(|w| write!(w, "constexpr ~{union_name}_storage_t() {{}}"))?;
                Ok(())
            },
            |w| w.writeln(|w| write!(w, "}} {union_name}_storage_t;")),
        )?;

        self.scoped(
            |w| w.writeln(|w| write!(w, "enum class {union_name}_variant_t {{")),
            |w| {
                w.writeln(|w| write!(w, "Empty = 0,"))?;
                for field in oneof.fields() {
                    let field_name = field.name();
                    let field_num = field.number();
                    w.writeln(|w| write!(w, "{field_name} = {field_num},"))?;
                }
                Ok(())
            },
            |w| w.writeln(|w| write!(w, "}};")),
       )?;

        self.writeln(|w| write!(w, "{union_name}_variant_t {union_name}_variant = {union_name}_variant_t::Empty;"))?;
        self.writeln(|w| write!(w, "{union_name}_storage_t {union_name}_storage;"))?;
        Ok(())
    }

    fn write_write_fields(&mut self, fields: &[FieldDescriptor], oneofs: &[OneofDescriptor]) -> std::io::Result<()> {
        if fields.is_empty() {
            self.writeln(|w| write!(w, "return Err<void>(Protobuf::Error::BadVariant);"))?;
        } else {
            self.scoped(
                |w| w.writeln(|w| write!(w, "switch (field_num) {{")),
                |w| {
                    for field in fields {
                        let field_num = field.number();
                        w.scoped(
                            |w| w.writeln(|w| write!(w, "case ({field_num}): {{")),
                            |w| {
                                let field_name = field.name();

                                use crate::ProtobufBindingsWriter;
                                let rft = field.runtime_field_type();
                                let field_type = Self::protobuf_type_to_native_type(
                                    &rft
                                );

                                let conv_type = match field.proto().type_() {
                                    Type::TYPE_FLOAT | Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 => "uint32_t",
                                    _ => "varint_t",
                                };

                                if let Some(oneof) = field_is_apart_of_union(&field, oneofs) {
                                    let union_name = oneof.name();
                                    match field.runtime_field_type() {
                                        RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(({field_type})val);"))?,
                                        _ => unreachable!(),
                                    }
                                } else {
                                    match field.runtime_field_type() {
                                        RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->{field_name} = std::bit_cast<{field_type}>(({conv_type})val);"))?,
                                        RuntimeFieldType::Repeated(..) => w.writeln(|w| write!(w, "this->{field_name}.push_back(std::bit_cast<{field_type}>(({conv_type})val));"))?,
                                        RuntimeFieldType::Map(..) => todo!(),
                                    }
                                }
                                w.writeln(|w| write!(w, "break;"))?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;
                    }
                    w.writeln(|w| write!(w, "default: return Err<void>(Protobuf::Error::BadVariant);"))?;
                    Ok(())
                },
                |w| w.writeln(|w| write!(w, "}}")),
            )?;
            self.writeln(|w| write!(w, "return Ok<void>();"))?;
        }
        Ok(())
    }
    
    fn write_field(&mut self, field: &FieldDescriptor, deps: &[ProtobufType], is_union: bool) -> std::io::Result<()> {
        let field_name = field.name();

        use crate::ProtobufBindingsWriter;

        let rft = field.runtime_field_type();

        let field_type = Self::protobuf_type_to_native_type( &rft);
        match field.runtime_field_type() {
            RuntimeFieldType::Singular(..) => {
                self.writeln(|w| {
                    if field.proto().proto3_optional() {
                        write!(w, "std::optional<")?;
                    }
                    write!(w, "{field_type}")?;

                    let mut deps_iter = deps.iter();

                    if let Some(dep) = deps_iter.next() {
                        write!(w, "<")?;
                        let mut c = 0;
                        w.write_nested_template_field(dep, field_name, &mut c)?;
                        while let Some(dep) = deps_iter.next() {
                            let mut c = 0;
                            w.write_nested_template_field(dep, field_name, &mut c)?;
                        }
                        write!(w, ">")?;
                    }

                    if field.proto().proto3_optional() {
                        write!(w, ">")?
                    }
                    write!(w, " {field_name}")?;

                    if !is_union {
                        if field.proto().proto3_optional() {
                            write!(w, " = std::nullopt")?;
                        } else {
                            match field.singular_default_value() {
                                ReflectValueRef::U32(v) => write!(w, " = {v}")?,
                                ReflectValueRef::U64(v) => write!(w, " = {v}")?,
                                ReflectValueRef::I32(v) => write!(w, " = {v}")?,
                                ReflectValueRef::I64(v) => write!(w, " = {v}")?,
                                ReflectValueRef::F32(v) => write!(w, " = {v}")?,
                                ReflectValueRef::F64(v) => write!(w, " = {v}")?,
                                ReflectValueRef::String(s) => {
                                    if !s.is_empty() {
                                        write!(w, r#" = "{s}""#)?
                                    } else {
                                        write!(w, " = str::new_(nullptr, 0);")?;
                                    }
                                }
                                ReflectValueRef::Message(m) => {
                                    let desc = m.descriptor_dyn();
                                    let name = desc.name();

                                    write!(w, " = {name}")?;

                                    if !deps.is_empty() {
                                        write!(w, "<>")?;
                                    }
                                    write!(w, "::default_()")?;
                                }
                                ReflectValueRef::Enum(e, _) => {
                                    let name = e.name();
                                    let def = e.default_value();
                                    let value = def.name();
                                    write!(w, " = {name}::{value}")?;
                                }
                                _ => todo!()
                            }
                        }
                    }

                    write!(w, ";")?;
                    Ok(())
                })?;
            }
            RuntimeFieldType::Repeated(..) => {
                self.writeln(|w| {
                    write!(w, "std::vector<{field_type}")?;

                    let mut deps_iter = deps.iter().rev();

                    let first = deps_iter.next().unwrap();

                    let mut first_dep_iter = first.deps();

                    let mut last = 0;

                    if let Some(fd) = first_dep_iter.next() {
                        write!(w, "<")?;
                        let mut c = 0;
                        w.write_nested_template_field(fd, field_name, &mut c)?;
                        while let Some(fd) = first_dep_iter.next() {
                            let mut c = 0;
                            w.write_nested_template_field(fd, field_name, &mut c)?;
                            last += c + 1;
                        }
                        last += c;
                        write!(w, ">")?;
                    }

                    write!(w, ", alloc_{field_name}_{last}> ")?;
                    write!(w, "{field_name};")?;
                    Ok(())
                })?;
            },
            RuntimeFieldType::Map(..) => todo!(),
        }
        Ok(())
    }

    fn write_nested_template(&mut self, tys: &ProtobufType, c: &mut usize, field_name: &str, first: &mut bool, write_default: bool, write_typename: bool) -> std::io::Result<()> {
        for ty in tys.deps() {
            self.write_nested_template(ty, c, field_name, first, write_default, write_typename)?;
        }
        match tys.field_type() {
            RuntimeFieldType::Repeated(..) => {
                let ty = str_from_runtime_type(tys.runtime_type());
                if !*first {
                    write!(self, ", ")?;
                } else {
                    *first = false;
                }
                if write_typename {
                    write!(self, "typename ")?;
                }
                write!(self, "alloc_{field_name}_{c}")?;

                if write_default {
                    write!(self, " = std::allocator<{ty}")?;
                }
                *c += 1;

                if tys.has_deps() && write_default {
                    let mut c = 0;
                    let mut first = true;
                    write!(self, "<")?;
                    for ty in tys.deps() {
                        self.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                    }
                    write!(self, ">")?;
                }

                if write_default {
                    write!(self, ">")?;
                }
            }
            RuntimeFieldType::Map(..) => todo!(),
            RuntimeFieldType::Singular(..) if !tys.has_deps() => {
                let ty = str_from_runtime_type(tys.runtime_type());
                if !*first {
                    write!(self, ", ")?;
                } else {
                    *first = false;
                }
                if write_typename {
                    write!(self, "typename ")?;
                }
                write!(self, "alloc_{field_name}_{c}")?;

                if write_default {
                    write!(self, " = std::allocator<{ty}")?;
                }
                *c += 1;

                if tys.has_deps() {
                    let mut c = 0;
                    let mut first = true;
                    write!(self, "<")?;
                    for ty in tys.deps() {
                        self.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                    }
                    write!(self, ">")?;
                }

                if write_default {
                    write!(self, ">")?;
                }
            },
            _ => (),
        };
        Ok(())
    }


    fn write_nested_template_field(&mut self, tys: &ProtobufType, field_name: &str, c: &mut usize) -> std::io::Result<()> {
        let mut first = true;
        self.write_nested_template(tys, c, field_name, &mut first, false, false)?;
        Ok(())
    }

    fn write_template_default(&mut self, tys: &ProtobufType, first: &mut bool, write_def: bool) -> std::io::Result<()> {
        for ty in tys.deps() {
            self.write_template_default(ty, first, write_def)?
        }

        let ty = str_from_runtime_type(tys.runtime_type());

        match tys.field_type() {
            RuntimeFieldType::Repeated(..) => {
                if !*first {
                    write!(self, ", ")?;
                } else {
                    *first = false;
                }

                write!(self, "std::allocator<{ty}")?;

                if tys.has_deps() {
                    write!(self, "<")?;
                    let mut first = true;

                    for ty in tys.deps() {
                        self.write_template_default(ty, &mut first, false)?;
                    }
                    write!(self, ">")?;
                }
                write!(self, ">")?;
            }
            RuntimeFieldType::Singular(..) => {
                
            }
            RuntimeFieldType::Map(..) => todo!(),
        }
        Ok(())
    }
}

impl std::io::Write for CppWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.inner.write(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

use std::io::Write;

impl crate::ProtobufBindingsWriter for CppWriter {
    type WriterOptions = CppWriterOptions;
    fn with_writer_options(&mut self, options: Self::WriterOptions) {
        self.options = options;
    }

    fn writer(&mut self) -> &mut impl std::io::Write {
        self
    }

    fn write_prelude(&mut self) -> std::io::Result<()> {
        if self.options.reflection_tests.is_some() {
            self.writeln(|w| write!(w, "#include <cassert>"))?;
        }


        writeln!(
            self,
            r#"#include <stdint.h>
#include <stddef.h>
#include <string>
#include <cstring>
#include <expected>
#include <vector>
#include <tuple>
#include <optional>
#include <type_traits>
#include <memory>
#include <array>


#include <bit>
#include <bitset>

#define TAG_TYPE_BITS 3
#define TAG_TYPE_MASK (1 << TAG_TYPE_BITS) - 1
#define MAX_FIELD_NUM ((2 << 29) - 1)

#define check_err(res) check_err_with_ret(void, res)

#define check_err_with_ret(ty, res) if (!res) {{ return Err<ty>(res.error()); }}

typedef uint64_t varint_t;
typedef float float32_t;
typedef double float64_t;

constexpr void copy_buffer(uint8_t* dst, const uint8_t* src, size_t len) {{
    if(std::is_constant_evaluated()) {{
        for(auto i = 0; i < len; i++) {{
            dst[i] = src[i];
        }}
    }} else {{
        memcpy(dst, src, len);
    }}
}}

constexpr size_t varint_size(varint_t varint) {{
    //equivalent to varint.lower_power_of_2().ilog2()
    return varint < 2 ? 1 : (std::bit_width(std::bit_floor(varint)) + 6) / 7;
}}

namespace Protobuf {{
    enum class Error {{
        BadMetadata,
        BadLength,
        BadVariant,
        BufferOOM,
    }};

    class Buffer {{
        public:
            virtual void set_write_len(size_t len) = 0;
            virtual void set_read_len(size_t len) = 0;
            /// used for write buffer
            virtual void write_bytes(const uint8_t* bytes, size_t len) = 0;

            constexpr Buffer() {{}}
            constexpr void clear_read() {{
                this->set_read_len(0);
            }}
            constexpr void clear_written() {{
                this->set_write_len(0);
            }}
            constexpr void clear() {{
                this->clear_read();
                this->clear_written();
            }}
            virtual size_t read_size() const  = 0;
            virtual size_t write_size() const = 0;
            virtual const uint8_t* written_bytes() const = 0;
            virtual uint8_t* written_bytes_mut() = 0;
            virtual size_t write_len() const = 0;
            virtual const uint8_t* read_bytes() const = 0;
            virtual uint8_t* read_bytes_mut() = 0;
            virtual size_t read_len() const = 0;
            constexpr const std::tuple<const uint8_t*, size_t> read_buf() const {{
                const std::tuple<const uint8_t*, size_t> out = {{this->read_bytes(), this->read_len()}};
                return out;
            }}

            constexpr const std::tuple<const uint8_t*, size_t> write_buf() const {{
                const std::tuple<const uint8_t*, size_t> out = {{this->written_bytes(), this->write_len()}};
                return out;
            }}

            constexpr const std::tuple<uint8_t*, size_t> write_buf_mut() {{
                const std::tuple<uint8_t*, size_t> out = {{this->written_bytes_mut(), this->write_len()}};
                return out;
            }}

            constexpr std::expected<void, Error> write_varint(varint_t varint) {{
              const auto size = varint_size(varint);

              auto actual_size = 0;
              const auto& [bytes, len] = this->write_buf_mut();
              if(len + size > this->write_size()) {{
                return std::unexpected(Error::BufferOOM);
              }}
              auto idx = 0;
              while(varint >= 0x80) {{
                actual_size += 1;
                bytes[len + idx] = ((uint8_t)varint) | 0x80;
                varint >>= 7;
                idx += 1;
              }}

              bytes[len + idx] = (uint8_t)varint & (~0x80);

              actual_size += 1;
              assert(size == actual_size);

              this->set_write_len(len + size);
              const std::expected<void, Error> out;
              return out;
            }}

            constexpr std::expected<void, Error> write_tag(varint_t field_num, uint8_t tag_kind) {{
                if(field_num > MAX_FIELD_NUM) {{
                    return std::unexpected(Error::BadVariant);
                }}
                const auto packed = (((varint_t) field_num) << TAG_TYPE_BITS) | tag_kind;
                return this->write_varint(packed);
            }}

            constexpr std::expected<void, Error> write_length_delimited(varint_t len, const uint8_t* data) {{
                const auto res = this->write_varint(len);
                if(!res) {{
                    return std::unexpected(res.error());
                }}
                const auto& [write_buf, write_len] = this->write_buf_mut();
                if (write_len + len > this->write_size()) {{
                    return std::unexpected(Error::BufferOOM);
                }}

                copy_buffer(&write_buf[write_len], data, len);
                this->set_write_len(write_len + len);
                const std::expected<void, Error> out;
                return out;
            }}

            constexpr std::expected<void, Error> write_32_bit(uint32_t bits) {{
                const auto& [write_buf, write_len] = this->write_buf_mut();
                if(write_len + 4 > this->write_size()) {{
                    return std::unexpected(Error::BufferOOM);
                }}
                const auto bytes = std::bit_cast<std::array<uint8_t, 4>>(bits);

                copy_buffer(&write_buf[write_len], bytes.data(), 4);
                this->set_write_len(write_len + 4);
                const std::expected<void, Error> out;
                return out;
            }}

            constexpr std::expected<void, Error> write_64_bit(uint64_t bits) {{
                const auto& [write_buf, write_len] = this->write_buf_mut();
                if(write_len + 8 > this->write_size()) {{
                    return std::unexpected(Error::BufferOOM);
                }}

                const auto bytes = std::bit_cast<std::array<uint8_t, 8>>(bits);
                copy_buffer(&write_buf[write_len], bytes.data(), 8);
                this->set_write_len(write_len + 8);
                const std::expected<void, Error> out;
                return out;
            }}
    }};

    template <size_t R_SIZE, size_t W_SIZE = R_SIZE>
    class SizedBuffer: public Buffer {{
        size_t w_len = 0;
        std::array<uint8_t, W_SIZE> write_buffer;
        size_t r_len = 0;
        std::array<uint8_t, W_SIZE> read_buffer;
        public:
            constexpr void set_write_len(size_t len) override {{
                this->w_len = len;
            }}
            constexpr void set_read_len(size_t len) override {{
                this->r_len = len;
            }}
            constexpr void write_bytes(const uint8_t* bytes, size_t len) override {{
                copy_buffer(this->write_buffer.data(), bytes, len);
                this->set_write_len(len);
            }}
            constexpr SizedBuffer() = default;
            constexpr ~SizedBuffer() = default;

            constexpr size_t read_size() const override {{
                return R_SIZE;
            }}

            constexpr size_t write_size() const override {{
                return W_SIZE;
            }}

            constexpr const uint8_t* written_bytes() const override {{
                return this->write_buffer.data();
            }}

            constexpr uint8_t* written_bytes_mut() override {{
                return this->write_buffer.data();
            }}

            constexpr size_t write_len() const override {{
                return this->w_len;
            }}

            constexpr const uint8_t* read_bytes() const override {{
                return this->read_buffer.data();
            }}

            constexpr uint8_t* read_bytes_mut() override {{
              return this->read_buffer.data();
            }}

            constexpr size_t read_len() const override {{
                return this->r_len;
            }}
    }};
}};


template <typename T> constexpr std::expected<T, Protobuf::Error> Err(const Protobuf::Error& err) {{
    return std::unexpected(err);
}}

template <typename T> constexpr std::expected<T, Protobuf::Error> Ok() {{
    const std::expected<T, Protobuf::Error> out;
    return out;
}}

template <typename T> constexpr std::expected<T, Protobuf::Error> Ok(const T& ok) {{
    const std::expected<T, Protobuf::Error> out = ok;
    return out;
}}

class bytes {{
    public:
        constexpr static bytes new_(const uint8_t* chars, size_t len) {{
            return bytes(chars, len);
        }}

        constexpr bytes(const uint8_t* chars, size_t len) {{
            this->byte_ptr = chars;
            this->length = len;
        }}

        constexpr size_t len() const {{
            return this->length;
        }}

        constexpr const uint8_t* ptr() const {{
            return this->byte_ptr;
        }}

        constexpr bool operator==(const bytes& rhs) const& {{
            if(this->length != rhs.length) {{
                return false;
            }}

            for(auto i = 0; i < rhs.len(); i++) {{
                if (this->ptr()[i] != rhs.ptr()[i]) {{
                    return false;
                }}
            }}
            return true;
        }}

        constexpr bool operator!=(const bytes& rhs) const& {{
            if(this->length != rhs.length) {{
                return true;
            }}

            for(auto i = 0; i < rhs.len(); i++) {{
                if (this->ptr()[i] != rhs.ptr()[i]) {{
                    return true;
                }}
            }}
            return false;
        }}

    private:
        size_t length = 0;
        const uint8_t* byte_ptr = nullptr;
}};

class str {{
    public:
        constexpr static str new_(const uint8_t* chars, size_t len) {{
            return str(chars, len);
        }}

        constexpr str(const uint8_t* chars, size_t len) {{
            this->characters = chars;
            this->length = len;
        }}

        constexpr size_t len() const {{
            return this->length;
        }}

        constexpr const uint8_t* chars() const {{
            return this->characters;
        }}

        constexpr std::string to_string() const {{
            return std::string((const char*)this->characters, this->length);
        }}

        constexpr bool operator==(const str& rhs) const& {{
            if(this->length != rhs.length) {{
                return false;
            }}

            for(auto i = 0; i < rhs.len(); i++) {{
                if (this->chars()[i] != rhs.chars()[i]) {{
                    return false;
                }}
            }}
            return true;
        }}

        constexpr bool operator!=(const str& rhs) const& {{
            if(this->length != rhs.length) {{
                return true;
            }}

            for(auto i = 0; i < rhs.len(); i++) {{
                if (this->chars()[i] != rhs.chars()[i]) {{
                    return true;
                }}
            }}
            return false;
        }}

    private:
        size_t length = 0;
        const uint8_t* characters = nullptr;
}};

template <typename T>
constexpr T get_from_bytes(const uint8_t* bytes, size_t idx) {{
    T num = 0;
    for(auto i = 0; i < sizeof(T); i++) {{
        num = (num << 8) + bytes[idx + sizeof(T) - 1 - i];
    }}
    return num;
}}

constexpr std::expected<varint_t, Protobuf::Error> get_varint(const uint8_t* bytes, size_t* index, size_t len) {{
    const auto first_byte = bytes[*index];
    varint_t varint = first_byte & (~0x80);
    auto valid = true;

    *index += 1;

    if (first_byte & 0x80) {{
      auto i = 1;
      valid = false;
      while(*index < len) {{
        const auto byte = bytes[*index];
        const auto masked = (varint_t)(byte & (~0x80));
        const auto shifted = masked << (0x7 * i);
        varint += shifted;

        *index += 1;
        i += 1;

        if(!(byte & 0x80)) {{
          valid = true;
          break;
        }}
      }}
    }}

    if(!valid) {{
        return Err<varint_t>(Protobuf::Error::BadMetadata);
    }}

    return Ok(varint);
}}

constexpr std::expected<std::tuple<uint8_t, varint_t>, Protobuf::Error> get_wire_format(const uint8_t* bytes, size_t* index, size_t len) {{
  const auto first_byte = bytes[*index];

  const auto wire_kind = first_byte & 0x7;
  varint_t field_num = first_byte >> 3;
  auto valid = true;

  *index += 1;

  if (first_byte & 0x80 ) {{
      auto i = 1;
      valid = false;
      while(*index < len) {{
        const auto byte = bytes[*index];
        const auto masked = (varint_t)(byte & (~0x80));
        const auto shifted = masked << (0x7 * i);
        field_num += shifted;

        *index += 1;
        i += 1;

        if(!(byte & 0x80)) {{
          valid = true;
          break;
        }}
      }}
  }}

  if(!valid) {{
      return Err<std::tuple<uint8_t, varint_t>>(Protobuf::Error::BadMetadata);
  }}

  const std::tuple<uint8_t, uint8_t> out = {{field_num, wire_kind}};
  return out;
}}


template<typename T>
constexpr std::expected<T, Protobuf::Error> parse_from_(const Protobuf::Buffer& buf, size_t start, size_t len) {{
  size_t idx = start;
  const auto bytes = buf.read_bytes();
  T out;
  while (idx < len) {{
    const auto fmt = get_wire_format(bytes, &idx, len);
    check_err_with_ret(T, fmt);
    const auto& [field_num, field_kind] = *fmt;
    switch (field_kind) {{
      case 0x00: {{
        const auto res = get_varint(bytes, &idx, len);
        check_err_with_ret(T, res);
        const auto write_res = out.write_varint(*res, field_num);
        check_err_with_ret(T, write_res);
        break;
      }}
      case 0x01: {{
        if (idx + 8 > len ) {{
          return Err<T>(Protobuf::Error::BadLength);
        }}

        const auto num = get_from_bytes<uint64_t>(bytes, idx);
        const auto write_res = out.write_64_bit(num, field_num);
        check_err_with_ret(T, write_res);
        idx += 8;
        break;
      }}
      case 0x02: {{
        const auto res = get_varint(bytes, &idx, len);
        check_err_with_ret(T, res);
        const auto field_len = *res;
        if(idx + field_len > len) {{
          return Err<T>(Protobuf::Error::BadLength);
        }}
        const auto write_res = out.write_length_delimited(buf, idx, field_len, field_num);
        check_err_with_ret(T, write_res);
        idx += field_len;
        break;
      }}
      case 0x05: {{
        if (idx + 4 > len ) {{
          return Err<T>(Protobuf::Error::BadLength);
        }}
        const auto num = get_from_bytes<uint32_t>(bytes, idx);
        const auto write_res = out.write_32_bit(num, field_num);
        check_err_with_ret(T, write_res);
        idx += 4;
        break;
      }}
      default: return Err<T>(Protobuf::Error::BadVariant);
    }}
  }}
  return Ok(out);
}}
"#
        )?;

        if self.options.generate_fuzz.is_some() || self.options.reflection_tests.is_some() {
            let max_len = self.options.reflection_tests.as_ref().map(|test| test.max_len).unwrap_or(1024);

            write!(self,
                   "
constexpr uint64_t seed(){{
  std::uint64_t shifted = 0;

  for( const auto c : __TIME__ )
  {{
    shifted <<= 8;
    shifted |= c;
  }}

  return shifted;
}}
template<typename T>
struct PCG
{{
  struct pcg32_random_t {{ std::uint64_t state=seed();  std::uint64_t inc=seed(); }};
  pcg32_random_t rng;

  constexpr T operator()() {{
    return (T)pcg32_random_r();
  }}

  private:
  constexpr std::uint64_t pcg32_random_r() {{
    std::uint64_t oldstate = rng.state;
    // Advance internal state
    rng.state = oldstate * 6364136223846793005ULL + (rng.inc|1);
    // Calculate output function (XSH RR), uses old state for max ILP
    std::uint64_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
    std::uint64_t rot = oldstate >> 59u;
    return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
  }}
}};

constexpr std::tuple<const uint8_t*, size_t> generate_random_bytes(size_t max_size = {max_len}) {{
    PCG<size_t> gen_bytes_len;

    const auto ceil = std::bit_ceil(max_size);
    const auto size_mask = ceil - 1;
    const auto len = gen_bytes_len() & size_mask;

    const auto bytes = new uint8_t[len];
    PCG<uint8_t> gen_byte;

    for(auto i = 0; i < len; i++) {{
        bytes[i] = gen_byte();
    }}

    std::tuple<const uint8_t*, size_t> out = {{bytes, len}};
    return out;
}}
")?;


        }

        Ok(())
    }
    fn write_file_header(&mut self, fd: &FileDescriptor) -> std::io::Result<()> {
        let pkg = fd.package();

        if !pkg.is_empty() {
            self.writeln(|w| write!(w, "namespace {pkg} {{"))?;
            self.increment_tab();
        }
        Ok(())
    }

    fn write_file_closer(&mut self, fd: &FileDescriptor) -> std::io::Result<()> {
        let pkg = fd.package();

        if !pkg.is_empty() {
            self.decrement_tab();
            self.writeln(|w| write!(w, "}}"))?;
        }

        if self.options.include_main {
            self.scoped(|w| w.writeln(|w| write!(w, "int main() {{")),
                |w| w.writeln(|w| write!(w, "return 0;")),
                |w| w.writeln(|w| write!(w, "}}")),
            )?;
        }
        Ok(())
    }

    fn write_enum(&mut self, _: &FileDescriptor, enm: &EnumDescriptor) -> std::io::Result<()> {
        let enum_name = enm.full_name();


        self.scoped(
            |w| w.writeln(|w| write!(w, "class {enum_name} {{")),
            |w| {
                w.scoped(
                |w| w.writeln(|w| write!(w, "public:")),
                |w| {
                    let bit_size = enm.values().count().next_power_of_two().ilog2();
                    let aligned_bit_size = ((bit_size + 7) / 8) * 8;
                    w.scoped(
                        |w| w.writeln(|w| write!(w, "enum {enum_name}_t : uint{aligned_bit_size}_t {{")),
                        |w| {
                            for variant in enm.values() {
                                let variant_name = variant.name();
                                let variant_num = variant.value();
                                w.writeln(|w| write!(w, "{variant_name} = {variant_num},"))?;
                            }
                            Ok(())
                        },
                        |w| w.writeln(|w| write!(w, "}};")),
                    )?;

                    let default_val = enm.default_value();
                    let default_variant = default_val.name();
                    w.writeln(|w| write!(w, "constexpr {enum_name}() {{ this->inner = {enum_name}_t::{default_variant}; }}"))?;
                    w.writeln(|w| write!(w, "constexpr {enum_name}({enum_name}_t variant) {{ this->inner = variant; }}"))?;
                    w.writeln(|w| write!(w, "constexpr ~{enum_name}() = default;"))?;
                    w.newline()?;
                    w.writeln(|w| write!(w, "constexpr operator const {enum_name}_t() const {{ return inner; }}"))?;
                    w.writeln(|w| write!(w, "explicit operator bool() const = delete;"))?;
                    w.writeln(|w| write!(w, "constexpr bool operator == ({enum_name} rhs) const& {{ return this->inner == rhs.inner; }}"))?;
                    w.writeln(|w| write!(w, "constexpr bool operator != ({enum_name} rhs) const& {{ return this->inner != rhs.inner; }}"))?;
                    w.newline()?;
                    w.scoped(
                        |w| w.writeln(|w| write!(w, "constexpr static std::expected<{enum_name}, Protobuf::Error> parse(varint_t varint) {{")),
                        |w| {
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "switch (varint) {{")),
                                |w| {
                                    for variant in enm.values() {
                                        let variant_num = variant.value();
                                        let variant_name = variant.name();
                                        w.writeln(|w| write!(w, "case {variant_num}: {{ return {enum_name}_t::{variant_name}; }}"))?;
                                    }
                                    w.writeln(|w| write!(w, "default: return Err<{enum_name}>(Protobuf::Error::BadVariant);"))?;
                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;
                            Ok(())
                        },
                        |w| w.writeln(|w| write!(w, "}}")),
                    )?;

                    w.scoped(
                        |w| w.writeln(|w| write!(w, "constexpr std::expected<void, Protobuf::Error> write_to(Protobuf::Buffer& buf) const {{")),
                        |w| {
                            w.writeln(|w| write!(w, "const auto varint = this->as_varint();"))?;
                            w.writeln(|w| write!(w, "return buf.write_varint(varint);"))?;
                            Ok(())
                        },
                        |w| w.writeln(|w| write!(w, "}}")),
                    )?;

                    w.scoped(
                        |w| w.writeln(|w| write!(w, "constexpr size_t dyn_size() const {{")),
                        |w| {
                            w.writeln(|w| write!(w, "return varint_size(this->as_varint());"))?;
                            Ok(())
                        },
                        |w| w.writeln(|w| write!(w, "}}")),
                    )?;


                    if w.options.reflection_tests.is_some() {
                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr static {enum_name} generate_random() {{")),
                            |w| {
                                let variant_count = enm.values().count();
                                let variant_count_mask = (variant_count + 1).next_power_of_two() - 1;
                                w.writeln(|w| write!(w, "PCG<size_t> gen_variant_count;"))?;
                                w.writeln(|w| write!(w, "const auto variant = (gen_variant_count() & {variant_count_mask});"))?;
                                
                                w.scoped(
                                    |w| w.writeln(|w| write!(w, "switch (variant) {{")),
                                    |w| {
                                        for (variant_num, variant) in enm.values().enumerate() {
                                            let variant_name = variant.name();

                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "case {variant_num} : {{")),
                                                |w| {
                                                    w.writeln(|w| write!(w, "return {enum_name}::{variant_name};"))?;
                                                    Ok(())
                                                },
                                                |w| w.writeln(|w| write!(w, "}}")),
                                            )?;
                                        }
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;

                                w.writeln(|w| write!(w, "return {enum_name}::generate_random();"))?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;
                    }

                    w.scoped(
                        |w| w.writeln(|w| write!(w, "constexpr static {enum_name} default_() {{")),
                        |w| {
                            w.writeln(|w| write!(w, "{enum_name} out;"))?;
                            w.writeln(|w| write!(w, "return out;"))?;
                            Ok(())
                        },
                        |w| w.writeln(|w| write!(w, "}}")),
                    )?;

                    Ok(())
                },
                |_| Ok(()),
            )?;
                w.scoped(
                    |w| w.writeln(|w| write!(w, "private:")),
                    |w| {
                        w.writeln(|w| write!(w, "{enum_name}_t inner;"))?;

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr varint_t as_varint() const {{")),
                            |w| {
                                w.scoped(
                                    |w| w.writeln(|w| write!(w, "switch (this->inner) {{")),
                                    |w| {
                                        for variant in enm.values() {
                                            let variant_name = variant.name();
                                            let variant_num = variant.value();
                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "case {enum_name}_t::{variant_name}: {{")),
                                                |w| {
                                                    w.writeln(|w| write!(w, "return {variant_num};"))?;
                                                    Ok(())
                                                },
                                                |w| w.writeln(|w| write!(w, "}}")),
                                            )?;
                                        }
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;
                        Ok(())
                    },
                    |_| Ok(()),
                        )?;
                Ok(())
            },
            |w| w.writeln(|w| write!(w, "}};")),
        )?;
        Ok(())
    }

    fn write_message(&mut self, _: &FileDescriptor, msg: &MessageDescriptor, collection_deps: &CollectionDeps) -> std::io::Result<()> {
        let msg_name = msg.name();

        let count = collection_deps.collection_deps().count();

        if count > 0 {
            self.writeln(|w| {
                write!(w, "template <")?;

                let mut deps_iter = collection_deps.deps_by_field_num();

                if let Some((field_num, allocs)) = deps_iter.next() {
                    let f = msg.field_by_number(*field_num as u32).unwrap();
                    let field_name = f.name();

                    let mut alloc_iter = allocs.iter().rev();

                    if let Some(alloc) = alloc_iter.next() {
                        let mut c = 0;
                        let mut first = true;
                        w.write_nested_template(alloc, &mut c, field_name, &mut first, true, true)?;

                        while let Some(alloc) = alloc_iter.next() {
                            write!(w, ", ")?;
                            let mut c = 0;
                            let mut first = true;
                            w.write_nested_template(alloc, &mut c, field_name, &mut first, true, true)?;
                            w.newline()?;
                        }
                    }

                    while let Some((field_num, allocs)) = deps_iter.next() {
                        write!(w, ", ")?;
                        let f = msg.field_by_number(*field_num as u32).unwrap();
                        let field_name = f.name();

                        let mut alloc_iter = allocs.iter().rev();

                        if let Some(alloc) = alloc_iter.next() {
                            let mut c = 0;
                            let mut first = true;
                            w.write_nested_template(alloc, &mut c, field_name, &mut first, true, true)?;

                            while let Some(alloc) = alloc_iter.next() {
                                write!(w, ", ")?;
                                let mut c = 0;
                                let mut first = true;
                                w.write_nested_template(alloc, &mut c, field_name, &mut first, true, true)?;
                                w.newline()?;
                            }
                        }
                    }
                }
                write!(w, ">")?;
                Ok(())
            })?;
        }

        self.scoped(
            |w| w.writeln(|w| write!(w, "class {msg_name} {{")), 
            |w| {
                let oneofs = msg.oneofs().filter(|oneof| !oneof.is_synthetic()).collect::<Vec<_>>();
                let fields = msg.fields().filter(|field| !oneofs.iter().any(|oneof| oneof.fields().any(|oneof_field| oneof_field.number() == field.number()))).collect::<Vec<_>>();

                // want to keep union members private so the variant data cannot be changed unless
                // the variant number is changed
                for oneof in &oneofs {
                    w.write_union(&oneof, collection_deps)?;
                }

                w.scoped(
                    |w| w.writeln(|w| write!(w, "public:")),
                    |w| {
                        if w.options.reflection_tests.is_some() {
                            w.writeln(|w| write!(w, "constexpr static bool reflection_test();"))?;
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "constexpr static {msg_name} generate_random() {{")),
                                |w| {
                                    if collection_deps.dep_count() > 0 {
                                        w.writeln(|w| {
                                            write!(w, "{msg_name}<")?;

                                            let mut first = true;
                                            let mut c = 0;
                                            for (field_num, deps) in collection_deps.deps_by_field_num() {
                                                let field = msg.field_by_number(*field_num as u32).unwrap();
                                                let name = field.name();
                                                for ty in deps {
                                                    w.write_nested_template(ty, &mut c, name, &mut first, false, false)?;
                                                }
                                                c = 0;
                                            }

                                            write!(w, "> out;")?;
                                            Ok(())
                                        })?;
                                    } else {
                                        w.writeln(|w| write!(w, "{msg_name} out;"))?;
                                    }

                                    for oneof in &oneofs {
                                        let union_name = oneof.name();
                                        let variant_count = oneof.fields().count() + 1;
                                        let variant_count_mask = (variant_count + 1).next_power_of_two() - 1;
                                        w.writeln(|w| write!(w, "PCG<size_t> gen_{union_name}_variant_count;"))?;
                                        w.writeln(|w| write!(w, "const auto {union_name}_variant = (gen_{union_name}_variant_count() & {variant_count_mask});"))?;

                                        w.scoped(
                                            |w| w.writeln(|w| write!(w, "switch ({union_name}_variant) {{")),
                                            |w| {
                                                for (num, variant) in oneof.fields().enumerate() {
                                                    let variant_name = variant.name();
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "case {num}: {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "out.{union_name}_variant = {union_name}_variant_t::{variant_name};"))?;

                                                            match variant.proto().type_() {
                                                                Type::TYPE_STRING => {
                                                                    w.writeln(|w| write!(w, "const auto& [bytes_{variant_name}, len_{variant_name}] = generate_random_bytes();"))?;
                                                                    w.writeln(|w| write!(w, "out.{union_name}_storage.{variant_name} = str::new_(bytes_{variant_name}, len_{variant_name});"))?;
                                                                }
                                                                Type::TYPE_BYTES => {
                                                                    w.writeln(|w| write!(w, "const auto& [bytes_{variant_name}, len_{variant_name}] = generate_random_bytes();"))?;
                                                                    w.writeln(|w| write!(w, "out.{union_name}_storage.{variant_name} = bytes::new_(bytes_{variant_name}, len_{variant_name});"))?;
                                                                }
                                                                _ => {
                                                                    generate_random_field(w, &variant, collection_deps)?;
                                                                }
                                                            }

                                                            if !matches!(variant.proto().type_(), Type::TYPE_BYTES | Type::TYPE_STRING) {
                                                                w.writeln(|w| write!(w, "out.{union_name}_storage.{variant_name} = rand_{variant_name};"))?;
                                                            }

                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                            )?;
                                                }
                                                Ok(())
                                            },
                                            |w| w.writeln(|w| write!(w, "}}")),
                                        )?;
                                    } 

                                    for field in &fields {
                                        let field_name = field.name();
                                        generate_random_field(w, field, collection_deps)?;

                                        let should_assign = matches!(field.runtime_field_type(), RuntimeFieldType::Repeated(..)) || matches!(field.proto().type_(), Type::TYPE_BYTES | Type::TYPE_STRING);

                                        if !should_assign {
                                            w.writeln(|w| write!(w, "out.{field_name} = rand_{field_name};"))?;
                                        }
                                    }
                                    w.writeln(|w| write!(w, "return out;"))?;
                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;

                            w.scoped(
                                |w| w.writeln(|w| write!(w, "constexpr void free_generated_data() const {{")),
                                |w| {
                                    for oneof in &oneofs {
                                        let union_name = oneof.name();
                                        if oneof.fields().any(|field| matches!(field.proto().type_(), Type::TYPE_MESSAGE | Type::TYPE_STRING)) {
                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "switch (this->{union_name}_variant) {{")),
                                                |w| {
                                                    for field in oneof.fields().filter(|f| matches!(f.proto().type_(), Type::TYPE_MESSAGE | Type::TYPE_STRING)) {
                                                        let field_name = field.name();
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "case {union_name}_variant_t::{field_name}: {{")),
                                                            |w| {
                                                                match field.proto().type_() {
                                                                    Type::TYPE_STRING => {
                                                                        w.writeln(|w| write!(w, "delete[] this->{union_name}_storage.{field_name}.chars();"))?;
                                                                    }
                                                                    Type::TYPE_BYTES => {
                                                                        w.writeln(|w| write!(w, "delete[] this->{union_name}_storage.{field_name}.ptr();"))?;
                                                                    }
                                                                    Type::TYPE_MESSAGE => {
                                                                        w.writeln(|w| write!(w, "this->{union_name}_storage.{field_name}.free_generated_data();"))?;
                                                                    }
                                                                    _ => (),
                                                                }
                                                                w.writeln(|w| write!(w, "break;"))?;
                                                                Ok(())
                                                            },
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?;
                                                    }
                                                    w.writeln(|w| write!(w, "default: break;"))?;

                                                    Ok(())
                                                },
                                                |w| w.writeln(|w| write!(w, "}}")),
                                            )?;
                                        }
                                    }

                                    for field in &fields {
                                        match field.runtime_field_type() {
                                            RuntimeFieldType::Singular(s) => match s {
                                                RuntimeType::Message(m) => {
                                                    let name = field.name();
                                                    if field.proto().proto3_optional() {
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "if(this->{name}) {{")),
                                                            |w| {
                                                                w.writeln(|w| write!(w, "this->{name}->free_generated_data();"))?;
                                                                Ok(())
                                                            },
                                                            |w| w.writeln(|w| write!(w, "}}"))
                                                                )?;
                                                    } else {
                                                        w.writeln(|w| write!(w, "this->{name}.free_generated_data();"))?;
                                                    }
                                                }
                                                RuntimeType::String => {
                                                    let name = field.name();

                                                    if field.proto().proto3_optional() {
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "if(this->{name}) {{")),
                                                            |w| {
                                                                w.writeln(|w| write!(w, "delete[] this->{name}->chars();"))?;
                                                                Ok(())
                                                            },
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                            )?;
                                                    } else {
                                                        w.writeln(|w| write!(w, "delete[] this->{name}.chars();"))?;
                                                    }
                                                }
                                                RuntimeType::VecU8 => {

                                                }
                                                _ => (),
                                            }
                                            RuntimeFieldType::Repeated(r) => match r {
                                                RuntimeType::Message(m) => {
                                                    let field_name = field.name();
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "for(const auto& item : this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "item.free_generated_data();"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                    )?;
                                                }
                                                RuntimeType::String => {
                                                    let field_name = field.name();
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "for(const auto& item : this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "delete[] item.chars();"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                    )?;
                                                }
                                                _ => (),
                                            },
                                            RuntimeFieldType::Map(..) => todo!(),
                                        }
                                    }
                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;
                        }

                        if let Some(fuzz_count) = &w.options.generate_fuzz {
                            todo!()
                        }

                        for field in &fields {
                            let deps = collection_deps.from_field_num(&field.number());
                            w.write_field(&field, deps, false)?;
                        }

                        let default_fields = if msg.file_descriptor().syntax() == protobuf::reflect::Syntax::Proto2 {
                            fields.iter().filter(|field| {
                                if let RuntimeFieldType::Singular(..) = field.runtime_field_type() {
                                    match field.singular_default_value() {
                                        ReflectValueRef::String(s) => !s.is_empty(),
                                        ReflectValueRef::Bytes(b) => !b.is_empty(),
                                        ReflectValueRef::Message(_) => false,
                                        _ => true,
                                    }
                                } else {
                                    false
                                }
                            }).collect::<Vec<_>>()
                        } else {
                            Vec::new()
                        };

                        if !default_fields.is_empty() {
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "constexpr {msg_name}() {{")),
                                |w| {
                                    for field in default_fields {
                                        let field_name = field.name();
                                        match field.singular_default_value() {
                                            ReflectValueRef::String(s) => {
                                                let str_len = s.len();
                                                w.writeln(|w| write!(w, "this->{field_name}.assign(\"{s}\", {str_len});"))?;
                                            }                                            
                                            ReflectValueRef::Bytes(b) => {
                                                let bytes_len = b.len();
                                                w.writeln(|w| {
                                                    write!(w, "const auto bytes = {{ ")?;
                                                    let mut iter = b.iter();
                                                    let first = iter.next().unwrap();
                                                    write!(w, "{first}")?;
                                                    while let Some(byte) = iter.next() {
                                                        write!(w, ", {byte}")?;
                                                    }
                                                    write!(w, " }};")?;
                                                    Ok(())
                                                })?;
                                                w.writeln(|w| write!(w, "this->{field_name}.assign(bytes, btes + {bytes_len});"))?;
                                            }
                                            ReflectValueRef::Enum(e, v) => {
                                                let enum_name = e.name();
                                                let variant = e.values().find(|variant| variant.value() == v).unwrap();
                                                let variant_name = variant.name();
                                                w.writeln(|w| write!(w, "this->{field_name} = {enum_name}::{variant_name};"))?;
                                            },
                                            default_val => w.writeln(|w| write!(w, "this->{field_name} = {default_val};"))?,
                                        }
                                    }
                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;
                        } else {
                            w.writeln(|w| write!(w, "constexpr {msg_name}() {{}}"))?;
                        }


                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr static {msg_name} default_() {{")),
                            |w| {
                                w.writeln(|w| write!(w, "{msg_name} out;"))?;
                                w.writeln(|w| write!(w, "return out;"))?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                            )?;

                        if oneofs.iter().any(|oneof| oneof.fields().any(|field| field.proto().type_() == Type::TYPE_MESSAGE && collection_deps.from_field_num(&field.number()).len() > 0)) {
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "constexpr {msg_name} operator=({msg_name} other) {{")),
                                |w| w.writeln(|w| write!(w, "return other;")),
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;
                        }

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr bool operator==(const {msg_name}& rhs) const& {{")),

                            |w| {
                                for oneof in &oneofs {
                                    let name = oneof.name();
                                    w.scoped(|w| w.writeln(|w| write!(w, "if (this->{name}_variant != rhs.{name}_variant) {{")),
                                     |w| w.writeln(|w| write!(w, "return false;")),
                                     |w| w.writeln(|w| write!(w, "}}"))
                                     )?;

                                    w.scoped(
                                        |w| w.writeln(|w| write!(w, "switch (this->{name}_variant) {{")),
                                        |w| {
                                            w.writeln(|w| write!(w, "case {name}_variant_t::Empty: {{ return true; }}"))?;
                                            for variant in oneof.fields() {
                                                let variant_name = variant.name();
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case {name}_variant_t::{variant_name}: {{")),
                                                    |w| {
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "if (this->{name}_storage.{variant_name} != rhs.{name}_storage.{variant_name}) {{")),
                                                            |w| w.writeln(|w| write!(w, "return false;")),
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                                )?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                        )?;
                                            }
                                            Ok(())
                                        },
                                        |w| w.writeln(|w| write!(w, "}}")),
                                    )?;
                                }

                                for field in &fields {
                                    let name = field.name();
                                    w.scoped(
                                        |w| w.writeln(|w| write!(w, "if (this->{name} != rhs.{name}) {{")),
                                        |w| w.writeln(|w| write!(w, "return false;")),
                                        |w| w.writeln(|w| write!(w, "}}")),
                                    )?;
                                }
                                w.writeln(|w| write!(w, "return true;"))?;

                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr bool operator!=(const {msg_name}& rhs) const& {{")),

                            |w| {
                                for oneof in &oneofs {
                                    let name = oneof.name();
                                    w.scoped(|w| w.writeln(|w| write!(w, "if (this->{name}_variant != rhs.{name}_variant) {{")),
                                     |w| w.writeln(|w| write!(w, "return true;")),
                                     |w| w.writeln(|w| write!(w, "}}"))
                                     )?;

                                    w.scoped(
                                        |w| w.writeln(|w| write!(w, "switch (this->{name}_variant) {{")),
                                        |w| {
                                            w.writeln(|w| write!(w, "case {name}_variant_t::Empty : {{ return false; }}"))?;
                                            for variant in oneof.fields() {
                                                let variant_name = variant.name();
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case {name}_variant_t::{variant_name}: {{")),
                                                    |w| {
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "if (this->{name}_storage.{variant_name} == rhs.{name}_storage.{variant_name}) {{")),
                                                            |w| w.writeln(|w| write!(w, "return false;")),
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                                )?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                        )?;
                                            }
                                            Ok(())
                                        },
                                        |w| w.writeln(|w| write!(w, "}}")),
                                    )?;
                                }

                                for field in &fields {
                                    let name = field.name();
                                    w.scoped(
                                        |w| w.writeln(|w| write!(w, "if (this->{name} == rhs.{name}) {{")),
                                        |w| w.writeln(|w| write!(w, "return false;")),
                                        |w| w.writeln(|w| write!(w, "}}")),
                                    )?;
                                }
                                w.writeln(|w| write!(w, "return true;"))?;

                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        for field in &fields {
                            if let RuntimeFieldType::Repeated(r) = field.runtime_field_type() {
                                let is_primitive = matches!(
                                    field.proto().type_(),
                                    Type::TYPE_DOUBLE
                                        | Type::TYPE_FLOAT
                                        | Type::TYPE_INT64
                                        | Type::TYPE_UINT64
                                        | Type::TYPE_INT32
                                        | Type::TYPE_FIXED64
                                        | Type::TYPE_FIXED32
                                        | Type::TYPE_BOOL
                                        | Type::TYPE_UINT32
                                        | Type::TYPE_SFIXED32
                                        | Type::TYPE_SFIXED64
                                        | Type::TYPE_SINT32
                                        | Type::TYPE_SINT64
                                        | Type::TYPE_ENUM
                                );

                                let is_packed = field.proto().options.get_or_default().packed.unwrap_or(match field.containing_message().file_descriptor().syntax() {
                                    protobuf::reflect::Syntax::Proto3 => is_primitive,
                                    _ => false,
                                });

                                if is_packed && !is_primitive {
                                    panic!("uh oh...");
                                }

                                let field_name = field.name();

                                w.scoped(
                                    |w| w.writeln(|w| write!(w, "constexpr size_t dyn_{field_name}_size() const {{")),
                                    |w| {
                                        w.writeln(|w| write!(w, "size_t sum = 0;"))?;
                                        let field_num = field.number();

                                        match field.proto().type_() {
                                            Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                w.writeln(|w| write!(w, "const auto len = this->{field_name}.size();"))?;
                                                if is_packed {
                                                    w.writeln(|w| write!(w, "sum += len * 4;"))?;
                                                } else {
                                                    w.writeln(|w| write!(w, "sum += len * (4 + varint_size({field_num} << 3));"))?;
                                                }
                                            }
                                            Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => {
                                                w.writeln(|w| write!(w, "const auto len = this->{field_name}.size();"))?;
                                                if is_packed {
                                                    w.writeln(|w| write!(w, "sum += len * 8;"))?;
                                                } else {
                                                    w.writeln(|w| write!(w, "sum += len * (8 + varint_size({field_num} << 3));"))?;
                                                }
                                            }
                                            Type::TYPE_SINT32 | Type::TYPE_SINT64 | Type::TYPE_INT32
                                            | Type::TYPE_INT64
                                            | Type::TYPE_UINT32
                                            | Type::TYPE_UINT64
                                            | Type::TYPE_BOOL => {
                                                if is_packed {
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "for(const auto& item : this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += varint_size(item);"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                    )?;
                                                } else {
                                                    w.writeln(|w| write!(w, "const auto len = this->{field_name}.size();"))?;
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "for(const auto& item : this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += varint_size(item);"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                    )?;
                                                    w.writeln(|w| write!(w, "sum += len * varint_size({field_num} << 3)"))?;
                                                }
                                            }
                                            Type::TYPE_ENUM => {
                                                if is_packed {
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "for(const auto& item : this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += item.dyn_size();"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                    )?;
                                                } else {
                                                    w.writeln(|w| write!(w, "const auto len = this->{field_name}.size();"))?;
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "for(const auto& item : this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += item.dyn_size();"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                    )?;
                                                    w.writeln(|w| write!(w, "sum += len * varint_size({field_num} << 3)"))?;
                                                }
                                            }
                                            Type::TYPE_MESSAGE => {
                                                w.writeln(|w| write!(w, "const auto len = this->{field_name}.size();"))?;
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "for(const auto& item : this->{field_name}) {{")),
                                                    |w| {
                                                        w.writeln(|w| write!(w, "sum += item.dyn_size();"))?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                )?;
                                                w.writeln(|w| write!(w, "sum += len * varint_size({field_num} << 3);"))?;
                                            }
                                            Type::TYPE_STRING => {}
                                            Type::TYPE_BYTES => {}
                                            _ => todo!(),
                                        }
                                        w.writeln(|w| write!(w, "return sum;"))?;
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;
                            }
                        }

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr size_t dyn_size() const {{")),
                            |w| {
                                w.writeln(|w| write!(w, "size_t sum = 0;"))?;
                                for oneof in &oneofs {
                                    let union_name = oneof.name();
                                    w.scoped(
                                        |w| w.writeln(|w| write!(w, "switch (this->{union_name}_variant) {{")),
                                        |w| {
                                            w.writeln(|w| write!(w, "case {union_name}_variant_t::Empty: {{ break; }}"))?;
                                            for field in oneof.fields() {
                                                let variant_name = field.name();
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case {union_name}_variant_t::{variant_name}: {{")),
                                                    |w| {
                                                        let variant_num = field.number();
                                                        w.writeln(|w| write!(w, "sum += varint_size({variant_num} << 3);"))?;
                                                        match field.proto().type_() {
                                                            Type::TYPE_MESSAGE => {
                                                                    w.writeln(|w| write!(w, "const auto {variant_name}_size = this->{union_name}_storage.{variant_name}.dyn_size();"))?;
                                                                    w.writeln(|w| write!(w, "sum += {variant_name}_size + varint_size({variant_name}_size);"))?;
                                                            }
                                                            Type::TYPE_ENUM => {
                                                                w.writeln(|w| write!(w, "sum += this->{union_name}_storage.{variant_name}.dyn_size();"))?;
                                                            }
                                                            Type::TYPE_INT32 | Type::TYPE_INT64 | Type::TYPE_UINT32 | Type::TYPE_UINT64 | Type::TYPE_BOOL | Type::TYPE_SINT32 | Type::TYPE_SINT64 => {
                                                                w.writeln(|w| write!(w, "sum += varint_size(this->{union_name}_storage.{variant_name});"))?;
                                                            }
                                                            Type::TYPE_STRING | Type::TYPE_BYTES => {
                                                                w.writeln(|w| write!(w, "const auto {variant_name}_size = this->{union_name}_storage.{variant_name}.len();"))?;
                                                                w.writeln(|w| write!(w, "sum += {variant_name}_size + varint_size({variant_name}_size);"))?;
                                                            }
                                                            Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                                w.writeln(|w| write!(w, "sum += 4;"))?;
                                                            }
                                                            Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => {
                                                                w.writeln(|w| write!(w, "sum += 8;"))?;
                                                            }
                                                            _ => todo!()
                                                        }
                                                        w.writeln(|w| write!(w, "break;"))?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                )?;
                                            }
                                            Ok(())
                                        },
                                        |w| w.writeln(|w| write!(w, "}}")),
                                    )?;
                                }

                                for field in &fields {
                                    let field_name = field.name();
                                    let field_num = field.number();

                                    let optional_field = field.proto().proto3_optional();

                                    match field.runtime_field_type() {
                                        RuntimeFieldType::Singular(_) => match field.proto().type_() {
                                            Type::TYPE_MESSAGE => {
                                                if optional_field {
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "if (this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                            w.writeln(|w| write!(w, "const auto {field_name} = *this->{field_name};"))?;
                                                            w.writeln(|w| write!(w, "const auto {field_name}_size = {field_name}.dyn_size();"))?;
                                                            w.writeln(|w| write!(w, "sum += {field_name}_size + varint_size({field_name}_size);"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}"))
                                                            )?;

                                                } else {
                                                    w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                    w.writeln(|w| write!(w, "const auto {field_name}_size = this->{field_name}.dyn_size();"))?;
                                                    w.writeln(|w| write!(w, "sum += {field_name}_size + varint_size({field_name}_size);"))?;
                                                }

                                            }
                                            Type::TYPE_ENUM => {
                                                if optional_field {
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "if(this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "const auto unwrapped = *this->{field_name};"))?;
                                                            w.writeln(|w| write!(w, "sum += unwrapped.dyn_size();"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                    )?;
                                                } else {
                                                    w.writeln(|w| write!(w, "sum += this->{field_name}.dyn_size();"))?;
                                                }
                                            }
                                            Type::TYPE_INT32 | Type::TYPE_INT64 | Type::TYPE_UINT32 | Type::TYPE_UINT64 | Type::TYPE_BOOL | Type::TYPE_SINT32 | Type::TYPE_SINT64 => {
                                                if optional_field {
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "if(this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                            w.writeln(|w| write!(w, "sum += varint_size(*this->{field_name});"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                            )?;
                                                } else {
                                                    w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                    w.writeln(|w| write!(w, "sum += varint_size(this->{field_name});"))?;
                                                }
                                            }
                                            Type::TYPE_STRING | Type::TYPE_BYTES => {
                                                if optional_field {
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "if (this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                            w.writeln(|w| write!(w, "const auto {field_name} = *this->{field_name};"))?;
                                                            w.writeln(|w| write!(w, "sum += varint_size({field_name}.len());"))?;
                                                            w.writeln(|w| write!(w, "sum += {field_name}.len();"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                            )?;
                                                } else {
                                                    w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                    w.writeln(|w| write!(w, "sum += varint_size(this->{field_name}.len());"))?;
                                                    w.writeln(|w| write!(w, "sum += this->{field_name}.len();"))?;
                                                }
                                            }
                                            Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                if optional_field {
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "if (this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;

                                                            w.writeln(|w| write!(w, "sum += 4;"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                            )?;
                                                } else {
                                                    w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                    w.writeln(|w| write!(w, "sum += 4;"))?;
                                                }
                                            }
                                            Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => {
                                                if optional_field {
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "if(this->{field_name}) {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                            w.writeln(|w| write!(w, "sum += 8;"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                            )?;
                                                } else {
                                                    w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                                    w.writeln(|w| write!(w, "sum += 8;"))?;
                                                }
                                            }
                                            _ => unreachable!()
                                        }
                                        RuntimeFieldType::Repeated(..) => {
                                            let is_primitive = matches!(
                                                field.proto().type_(),
                                                Type::TYPE_DOUBLE
                                                    | Type::TYPE_FLOAT
                                                    | Type::TYPE_INT64
                                                    | Type::TYPE_UINT64
                                                    | Type::TYPE_INT32
                                                    | Type::TYPE_FIXED64
                                                    | Type::TYPE_FIXED32
                                                    | Type::TYPE_BOOL
                                                    | Type::TYPE_UINT32
                                                    | Type::TYPE_SFIXED32
                                                    | Type::TYPE_SFIXED64
                                                    | Type::TYPE_SINT32
                                                    | Type::TYPE_SINT64
                                                    | Type::TYPE_ENUM
                                            );

                                            let is_packed = field.proto().options.get_or_default().packed.unwrap_or(match field.containing_message().file_descriptor().syntax() {
                                                protobuf::reflect::Syntax::Proto3 => is_primitive,
                                                _ => false,
                                            });

                                            if is_packed {
                                                w.writeln(|w| write!(w, "sum += varint_size({field_num} << 3);"))?;
                                            }

                                            w.writeln(|w| write!(w, "const auto {field_name}_size = this->dyn_{field_name}_size();"))?; 

                                            if is_packed {
                                                w.writeln(|w| write!(w, "sum += {field_name}_size + varint_size({field_name}_size);"))?;
                                            } else {
                                                w.writeln(|w| write!(w, "sum += {field_name}_size;"))?;
                                            }
                                        }
                                        RuntimeFieldType::Map(..) => todo!(),
                                    }
                                }
                                w.writeln(|w| write!(w, "return sum;"))?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        let needs_explicit_drop = oneofs.iter().any(|oneof| oneof.fields().any(|field| matches!(field.proto().type_(), Type::TYPE_STRING | Type::TYPE_BYTES | Type::TYPE_MESSAGE)));
                        if needs_explicit_drop {
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "constexpr ~{msg_name}() {{")),
                                |w| {
                                    for oneof in &oneofs {
                                        let explicit_drop_variants = oneof.fields().filter(|variant| matches!(variant.proto().type_(), Type::TYPE_MESSAGE)).collect::<Vec<_>>();
                                        if !explicit_drop_variants.is_empty() {
                                            let union_name = oneof.name();
                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "switch (this->{union_name}_variant) {{")),
                                                |w| {
                                                    for variant in explicit_drop_variants {
                                                        let variant_name = variant.name();
                                                        let rft = variant.runtime_field_type();

                                                        let variant_type = Self::protobuf_type_to_native_type( &rft                                                        );
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "case {union_name}_variant_t::{variant_name}: {{")),
                                                            |w| {
                                                                w.scoped(
                                                                    |w| w.writeln(|w| {
                                                                        write!(w, "if(!std::is_trivially_destructible<{variant_type}")?;
                                                                        let variant_num = variant.number();
                                                                        if variant.proto().type_() == Type::TYPE_MESSAGE && collection_deps.from_field_num(&variant_num).len() > 0 {
                                                                            write!(w, "<")?;
                                                                            let deps = collection_deps.from_field_num(&variant.number());
                                                                            let field_name = variant.name();

                                                                            let mut first = true;
                                                                            let mut c = 0;

                                                                            for ty in deps {
                                                                                w.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                                                                            }
                                                                            write!(w, ">")?;
                                                                        }
                                                                        write!(w, ">::value) {{")?;
                                                                        Ok(())
                                                                    }),
                                                                    |w| w.writeln(|w| write!(w, "std::destroy_at(&(this->{union_name}_storage.{variant_name}));")),
                                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                                )?;
                                                                w.writeln(|w| write!(w, "break;"))?;
                                                                Ok(())
                                                            },
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?
                                                    }
                                                    w.writeln(|w| write!(w, "default: break;"))?;
                                                    Ok(())
                                                }, 
                                                |w| w.writeln(|w| write!(w, "}}"))
                                            )?;
                                        }
                                    }

                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;

                            w.scoped(
                                |w| w.writeln(|w| write!(w, "constexpr {msg_name}(const {msg_name}& src) {{")),
                                |w| {
                                    for oneof in &oneofs {
                                        let union_name = oneof.name();
                                        w.writeln(|w| write!(w, "this->{union_name}_variant = src.{union_name}_variant;"))?;
                                        w.scoped(
                                            |w| w.writeln(|w| write!(w, "switch (src.{union_name}_variant) {{")),
                                            |w| {
                                                w.writeln(|w| write!(w, "case {union_name}_variant_t::Empty: {{ break; }}"))?;
                                                for variant in oneof.fields() {
                                                    let variant_name = variant.name();
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "case {union_name}_variant_t::{variant_name}: {{")),
                                                        |w| {
                                                            w.writeln(|w| write!(w, "this->{union_name}_storage.{variant_name} = src.{union_name}_storage.{variant_name};"))?;
                                                            w.writeln(|w| write!(w, "break;"))?;
                                                            Ok(())
                                                        },
                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                    )?;
                                                }
                                                Ok(())
                                            },
                                            |w| w.writeln(|w| write!(w, "}}")),
                                        )?;
                                        for field in &fields {
                                            let field_name = field.name();
                                            w.writeln(|w| write!(w, "this->{field_name} = src.{field_name};"))?;
                                        }
                                    }
                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;
                        }

                        for oneof in &oneofs {
                            let union_name = oneof.name();

                            w.scoped(
                                |w| w.writeln(|w| write!(w, "constexpr bool {union_name}_is_empty() const {{")),
                                |w| w.writeln(|w| write!(w, "return this->{union_name}_variant == {union_name}_variant_t::Empty;")),
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;

                            for variant in oneof.fields() {
                                let variant_name = variant.name();
                                let rft = variant.runtime_field_type();
                                let variant_type = Self::protobuf_type_to_native_type(
                                    &rft
                                );
                                w.scoped(
                                    |w| w.writeln(|w| {
                                        write!(w, "constexpr std::optional<{variant_type}")?;
                                        let variant_num = variant.number();

                                        if variant.proto().type_() == Type::TYPE_MESSAGE && collection_deps.from_field_num(&variant_num).len() > 0 {
                                            write!(w, "<")?;
                                            let deps = collection_deps.from_field_num(&variant.number());
                                            let field_name = variant.name();

                                            let mut first = true;
                                            let mut c = 0;

                                            for ty in deps {
                                                w.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                                            }
                                            write!(w, ">")?;
                                        }
                                        write!(w, "> {union_name}_as_{variant_name}() const {{")?;
                                        Ok(())
                                    }),
                                    |w| {
                                        w.scoped(
                                            |w| w.writeln(|w| write!(w, "if (this->{union_name}_variant == {union_name}_variant_t::{variant_name}) {{")),
                                            |w| w.writeln(|w| write!(w, "return this->{union_name}_storage.{variant_name};")),
                                            |w| w.writeln(|w| write!(w, "}}")),
                                        )?;
                                        w.writeln(|w| write!(w, "return std::nullopt;"))?;
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;
                                w.scoped(
                                    |w| w.writeln(|w| {
                                        write!(w, "constexpr void set_{union_name}_to_{variant_name}({variant_type}")?;
                                        let variant_num = variant.number();

                                        if variant.proto().type_() == Type::TYPE_MESSAGE && collection_deps.from_field_num(&variant_num).len() > 0 {
                                            write!(w, "<")?;
                                            let deps = collection_deps.from_field_num(&variant.number());
                                            let field_name = variant.name();

                                            let mut first = true;
                                            let mut c = 0;

                                            for ty in deps {
                                                w.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                                            }
                                            write!(w, ">")?;
                                        }

                                        write!(w, " {variant_name}) {{")?;

                                        Ok(())
                                    }),
                                    |w| {
                                        let explicit_drop_variants = oneof.fields().filter(|variant| matches!(variant.proto().type_(), Type::TYPE_MESSAGE)).collect::<Vec<_>>();
                                        if !explicit_drop_variants.is_empty() {
                                            let union_name = oneof.name();
                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "switch (this->{union_name}_variant) {{")),
                                                |w| {
                                                    for variant in explicit_drop_variants {
                                                        let variant_name = variant.name();
                                                        let rft = variant.runtime_field_type();
                                                        let variant_type = Self::protobuf_type_to_native_type(
                                                            &rft
                                                        );
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "case {union_name}_variant_t::{variant_name}: {{")),
                                                            |w| {
                                                                w.scoped(
                                                                    |w| w.writeln(|w| {
                                                                        write!(w, "if(!std::is_trivially_destructible<{variant_type}")?;
                                                                        let variant_num = variant.number();
                                                                        if variant.proto().type_() == Type::TYPE_MESSAGE && collection_deps.from_field_num(&variant_num).len() > 0 {
                                                                            write!(w, "<")?;
                                                                            let deps = collection_deps.from_field_num(&variant.number());
                                                                            let field_name = variant.name();

                                                                            let mut first = true;
                                                                            let mut c = 0;

                                                                            for ty in deps {
                                                                                w.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                                                                            }
                                                                            write!(w, ">")?;
                                                                        }
                                                                        write!(w, ">::value ) {{")?;
                                                                        Ok(())
                                                                    }),
                                                                    |w| w.writeln(|w| write!(w, "std::destroy_at(&(this->{union_name}_storage.{variant_name}));")),
                                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                                )?;
                                                                w.writeln(|w| write!(w, "break;"))?;
                                                                Ok(())
                                                            },
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?
                                                    }
                                                    w.writeln(|w| write!(w, "default: break;"))?;
                                                    Ok(())
                                                }, 
                                                |w| w.writeln(|w| write!(w, "}}"))
                                            )?;
                                        }
                                        w.writeln(|w| write!(w, "this->{union_name}_variant = {union_name}_variant_t::{variant_name};"))?;
                                        w.writeln(|w| write!(w, "this->{union_name}_storage.{variant_name} = {variant_name};"))?;
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;
                            }
                        }

                        let get_wire_type = |field: &FieldDescriptor| {
                            match field.runtime_field_type() {
                                RuntimeFieldType::Singular(..) => match field.proto().type_() {
                                    Type::TYPE_INT32
                                    | Type::TYPE_INT64
                                    | Type::TYPE_UINT32
                                    | Type::TYPE_UINT64
                                    | Type::TYPE_SINT32
                                    | Type::TYPE_SINT64
                                    | Type::TYPE_BOOL
                                    | Type::TYPE_ENUM => 0,
                                    Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => 1,
                                    Type::TYPE_STRING | Type::TYPE_BYTES | Type::TYPE_MESSAGE => 2,
                                    Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => 5,
                                    _ => todo!(),
                                }
                                RuntimeFieldType::Repeated(..) => {
                                    let is_primitive = matches!(
                                        field.proto().type_(),
                                        Type::TYPE_DOUBLE
                                            | Type::TYPE_FLOAT
                                            | Type::TYPE_INT64
                                            | Type::TYPE_UINT64
                                            | Type::TYPE_INT32
                                            | Type::TYPE_FIXED64
                                            | Type::TYPE_FIXED32
                                            | Type::TYPE_BOOL
                                            | Type::TYPE_UINT32
                                            | Type::TYPE_SFIXED32
                                            | Type::TYPE_SFIXED64
                                            | Type::TYPE_SINT32
                                            | Type::TYPE_SINT64
                                            | Type::TYPE_ENUM
                                    );

                                    let is_packed = field.proto().options.get_or_default().packed.unwrap_or(match field.containing_message().file_descriptor().syntax() {
                                        protobuf::reflect::Syntax::Proto3 => is_primitive,
                                        _ => false,
                                    });

                                    if is_packed {
                                        2
                                    } else {
                                        match field.proto().type_() {
                                            Type::TYPE_INT32
                                            | Type::TYPE_INT64
                                            | Type::TYPE_UINT32
                                            | Type::TYPE_UINT64
                                            | Type::TYPE_SINT32
                                            | Type::TYPE_SINT64
                                            | Type::TYPE_BOOL
                                            | Type::TYPE_ENUM => 0,
                                            Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => 1,
                                            Type::TYPE_STRING | Type::TYPE_BYTES | Type::TYPE_MESSAGE => 2,
                                            Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => 5,
                                            _ => todo!(),
                                        }
                                    }
                                },
                                RuntimeFieldType::Map(..) => todo!(),
                            }
                        };

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr std::expected<void, Protobuf::Error> write_to(Protobuf::Buffer& buf) const {{")),
                            |w| {
                                for oneof in &oneofs {
                                    let union_name = oneof.name();
                                    w.scoped(
                                        |w| w.writeln(|w| write!(w, "switch (this->{union_name}_variant) {{")),
                                        |w| {
                                            w.writeln(|w| write!(w, "case {union_name}_variant_t::Empty: {{ break; }}"))?;
                                            for variant in oneof.fields() {
                                                let variant_name = variant.name();
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case {union_name}_variant_t::{variant_name}: {{")),
                                                    |w| {
                                                        let wire_type = get_wire_type(&variant);
                                                        let variant_id = variant.number();
                                                        w.writeln(|w| write!(w, "const auto variant_res = buf.write_tag({variant_id}, {wire_type});"))?;
                                                        w.writeln(|w| write!(w, "check_err(variant_res);"))?;
                                                        match variant.runtime_field_type() {
                                                            RuntimeFieldType::Singular(..) => {
                                                                match variant.proto().type_() {
                                                                    Type::TYPE_BOOL | Type::TYPE_INT32 | Type::TYPE_INT64 | Type::TYPE_UINT32 | Type::TYPE_UINT64 => w.writeln(|w| write!(w, "const auto res = buf.write_varint(this->{union_name}_storage.{variant_name});"))?,
                                                                    Type::TYPE_SINT32 | Type::TYPE_SINT64 => {
                                                                        let size = if let Type::TYPE_SINT32 = variant.proto().type_() {
                                                                            32
                                                                        } else {
                                                                            64
                                                                        };
                                                                        w.writeln(|w| write!(w, "const auto raw = this->{union_name}_storage.{variant_name};"))?;
                                                                        w.writeln(|w| write!(w, "const auto enc = (raw >> {size} - 1) ^ (raw << 1);"))?;
                                                                        w.writeln(|w| write!(w, "const auto res = buf.write_varint(enc);"))?;
                                                                    }
                                                                    Type::TYPE_STRING => {
                                                                        w.writeln(|w| write!(w, "const auto str = this->{union_name}_storage.{variant_name};"))?;
                                                                        w.writeln(|w| write!(w, "const auto res = buf.write_length_delimited(str.len(), str.chars());"))?;
                                                                    }
                                                                    Type::TYPE_BYTES => {
                                                                        w.writeln(|w| write!(w, "const auto bytes = this->{union_name}_storage.{variant_name};"))?;
                                                                        w.writeln(|w| write!(w, "const auto res = buf.write_length_delimited(bytes.len(), bytes.ptr());"))?;
                                                                    }
                                                                    _ => w.writeln(|w| write!(w, "const auto res = this->{union_name}_storage.{variant_name}.write_to(buf);"))?,
                                                                }
                                                            }
                                                            _ => unreachable!(),
                                                        }

                                                        w.writeln(|w| write!(w, "check_err(res);"))?;
                                                        w.writeln(|w| write!(w, "break;"))?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                )?;
                                            }
                                            Ok(())
                                        },
                                        |w| w.writeln(|w| write!(w, "}}")),
                                    )?; 
                                }

                                for field in &fields {
                                    let field_name = field.name();
                                    if field.proto().proto3_optional() {
                                        w.writeln(|w| write!(w, "if(this->{field_name}) {{"))?;
                                        w.increment_tab();
                                        w.writeln(|w| write!(w, "const auto {field_name} = *(this->{field_name});"))?;
                                    } else {
                                        w.writeln(|w| write!(w, "const auto {field_name} = this->{field_name};"))?;
                                    }

                                    let wire_tag = get_wire_type(&field);
                                    let field_id = field.number();


                                    match field.runtime_field_type() {
                                        RuntimeFieldType::Singular(..) => {
                                            w.writeln(|w| write!(w, "const auto {field_name}_tag_res = buf.write_tag({field_id}, {wire_tag});"))?;
                                            w.writeln(|w| write!(w, "check_err({field_name}_tag_res);"))?;
                                            match field.proto().type_() {
                                                Type::TYPE_ENUM => w.writeln(|w| write!(w, "const auto {field_name}_res = {field_name}.write_to(buf);"))?,
                                                Type::TYPE_MESSAGE => {
                                                    w.writeln(|w| write!(w, "const auto {field_name}_len = {field_name}.dyn_size();"))?;
                                                    w.writeln(|w| write!(w, "const auto {field_name}_len_res = buf.write_varint({field_name}_len);"))?;
                                                    w.writeln(|w| write!(w, "check_err({field_name}_len_res);"))?;
                                                    w.writeln(|w| write!(w, "const auto {field_name}_res = {field_name}.write_to(buf);"))?
                                                }
                                                Type::TYPE_STRING => w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_length_delimited({field_name}.len(), {field_name}.chars());"))?,
                                                Type::TYPE_BYTES => w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_length_delimited({field_name}.len(), {field_name}.ptr());"))?,
                                                Type::TYPE_SINT32 | Type::TYPE_SINT64 => {
                                                    let size = if let Type::TYPE_SINT32 = field.proto().type_() {
                                                        32
                                                    } else {
                                                        64
                                                    };
                                                    w.writeln(|w| write!(w, "const auto {field_name}_enc = ({field_name} >> {size} - 1) ^ ({field_name} << 1);"))?;
                                                    w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_varint({field_name}_enc);"))?;
                                                }
                                                Type::TYPE_INT32
                                                | Type::TYPE_INT64
                                                | Type::TYPE_UINT32
                                                | Type::TYPE_UINT64
                                                | Type::TYPE_BOOL => w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_varint({field_name});"))?,
                                                Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => {
                                                    w.writeln(|w| write!(w, "const auto {field_name}_64 = std::bit_cast<uint64_t>({field_name});"))?;
                                                    w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_64_bit({field_name}_64);"))?;
                                                }
                                                Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                    w.writeln(|w| write!(w, "const auto {field_name}_u32 = std::bit_cast<uint32_t>({field_name});"))?;
                                                    w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_32_bit({field_name}_u32);"))?;
                                                }
                                                _ => todo!()
                                            }
                                            w.writeln(|w| write!(w, "check_err({field_name}_res);"))?;
                                        }
                                        RuntimeFieldType::Repeated(..) => {
                                            let is_primitive = matches!(
                                                field.proto().type_(),
                                                Type::TYPE_DOUBLE
                                                    | Type::TYPE_FLOAT
                                                    | Type::TYPE_INT64
                                                    | Type::TYPE_UINT64
                                                    | Type::TYPE_INT32
                                                    | Type::TYPE_FIXED64
                                                    | Type::TYPE_FIXED32
                                                    | Type::TYPE_BOOL
                                                    | Type::TYPE_UINT32
                                                    | Type::TYPE_SFIXED32
                                                    | Type::TYPE_SFIXED64
                                                    | Type::TYPE_SINT32
                                                    | Type::TYPE_SINT64
                                                    | Type::TYPE_ENUM
                                            );

                                            let is_packed = field.proto().options.get_or_default().packed.unwrap_or(match field.containing_message().file_descriptor().syntax() {
                                                protobuf::reflect::Syntax::Proto3 => is_primitive,
                                                _ => false,
                                            });

                                            if is_packed {
                                                w.writeln(|w| write!(w, "const auto {field_name}_tag_res = buf.write_tag({field_id}, {wire_tag});"))?;
                                                w.writeln(|w| write!(w, "check_err({field_name}_tag_res);"))?;

                                                w.writeln(|w| write!(w, "const auto len_{field_name}_res = buf.write_varint(this->dyn_{field_name}_size());"))?;
                                                w.writeln(|w| write!(w, "check_err(len_{field_name}_res);"))?;
                                            }

                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "for (const auto& item : this->{field_name}) {{")),
                                                |w| {
                                                    if is_packed {
                                                        match field.proto().type_() {
                                                            Type::TYPE_SINT32 | Type::TYPE_SINT64 => {
                                                                let size = if let Type::TYPE_SINT32 = field.proto().type_() {
                                                                    32
                                                                } else {
                                                                    64
                                                                };
                                                                w.writeln(|w| write!(w, "const auto item_enc = (item  >> {size} - 1) ^ (item << 1);"))?;
                                                                w.writeln(|w| write!(w, "const auto item_ret = buf.write_varint(item_enc);"))?;
                                                            }

                                                            Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => {
                                                                w.writeln(|w| write!(w, "const auto item_ret = buf.write_64_bit(std::bit_cast<uint64_t>(item));"))?;
                                                            }
                                                            Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                                w.writeln(|w| write!(w, "const auto item_ret = buf.write_32_bit(std::bit_cast<uint32_t>(item));"))?;
                                                            }
                                                            Type::TYPE_ENUM => w.writeln(|w| write!(w, "const auto item_ret = item.write_to(buf);"))?,
                                                                Type::TYPE_INT32
                                                                | Type::TYPE_INT64
                                                                | Type::TYPE_UINT32
                                                                | Type::TYPE_UINT64
                                                                | Type::TYPE_BOOL => w.writeln(|w| write!(w, "const auto item_ret = buf.write_varint(item);"))?,
                                                                _ => unreachable!()
                                                            }
                                                    } else {
                                                        let wire_type = get_wire_type(&field);
                                                        let field_id = field.number();
                                                        w.writeln(|w| write!(w, "const auto wire_ret = buf.write_tag({field_id}, {wire_type});"))?;
                                                        w.writeln(|w| write!(w, "check_err(wire_ret);"))?;
                                                        match field.proto().type_() {
                                                            Type::TYPE_ENUM => w.writeln(|w| write!(w, "const auto item_ret = item.write_to(buf);"))?,
                                                            Type::TYPE_MESSAGE => {
                                                                w.writeln(|w| write!(w, "const auto len_ret = buf.write_varint(item.dyn_size());"))?;
                                                                w.writeln(|w| write!(w, "check_err(len_ret);"))?;
                                                                w.writeln(|w| write!(w, "const auto item_ret = item.write_to(buf);"))?;
                                                            }
                                                            Type::TYPE_INT32
                                                            | Type::TYPE_INT64
                                                            | Type::TYPE_UINT32
                                                            | Type::TYPE_UINT64
                                                            | Type::TYPE_BOOL => w.writeln(|w| write!(w, "const auto item_ret = buf.write_varint(item);"))?,
                                                            Type::TYPE_SINT32 | Type::TYPE_SINT64 => {
                                                                let size = if let Type::TYPE_SINT32 = field.proto().type_() {
                                                                    32
                                                                } else {
                                                                    64
                                                                };
                                                                w.writeln(|w| write!(w, "const auto item_enc = (item  >> {size} - 1) ^ (item << 1);"))?;
                                                                w.writeln(|w| write!(w, "const auto item_ret = buf.write_varint(item_enc);"))?;
                                                            }
                                                            Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => {
                                                                w.writeln(|w| write!(w, "const auto item_ret = buf.write_64_bit(uint64_t)item);"))?;
                                                            }
                                                            Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                                w.writeln(|w| write!(w, "const auto item_ret = buf.write_32_bit((uint32_t)item);"))?;
                                                            }
                                                            Type::TYPE_BYTES => w.writeln(|w| write!(w, "const auto item_ret = buf.write_length_delimited(item.len(), item.ptr());"))?,
                                                            Type::TYPE_STRING => w.writeln(|w| write!(w, "const auto item_ret = buf.write_length_delimited(item.len(), item.chars());"))?,
                                                            _ => unreachable!(),
                                                        }
                                                    }
                                                    w.writeln(|w| write!(w, "check_err(item_ret);"))?;
                                                    Ok(())
                                                },
                                                |w| w.writeln(|w| write!(w, "}}")),
                                            )?;
                                        }
                                        RuntimeFieldType::Map(..) => todo!(),
                                    }

                                    if field.proto().proto3_optional() {
                                        w.decrement_tab();
                                        w.writeln(|w| write!(w, "}}"))?;
                                    }
                                }
                                w.writeln(|w| write!(w, "return Ok<void>();"))?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr std::expected<void, Protobuf::Error> write_varint(varint_t val, varint_t field_num) {{")),
                            |w| {
                                let varint_fields = get_fields_with_type(&msg, |ty| matches!(ty, Type::TYPE_INT32 | Type::TYPE_INT64 | Type::TYPE_UINT32 | Type::TYPE_UINT64 | Type::TYPE_BOOL | Type::TYPE_ENUM));
                                w.scoped(
                                    |w| w.writeln(|w| write!(w, "switch (field_num) {{")),
                                    |w| {
                                        for field in varint_fields {
                                            let field_num = field.number();
                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "case ({field_num}): {{")),
                                                |w| {
                                                    let field_name = field.name();
                                                    let rft = field.runtime_field_type();
                                                    let field_type = Self::protobuf_type_to_native_type(
                                                        &rft
                                                    );
                                                    w.writeln(|w| {
                                                        match field.proto().type_() {
                                                            Type::TYPE_SINT32 | Type::TYPE_SINT64 => write!(w, "const auto out = (val >> 1) ^ -(val & 1);")?,
                                                            Type::TYPE_ENUM => {
                                                                let runtime_ty = field.runtime_field_type();
                                                                let field_ty = Self::protobuf_type_to_native_type(&runtime_ty);
                                                                w.writeln(|w| write!(w, "const auto res = {field_ty}::parse(val);"))?;
                                                                w.writeln(|w| write!(w, "check_err(res);"))?;
                                                            }
                                                            Type::TYPE_INT32
                                                            | Type::TYPE_INT64
                                                            | Type::TYPE_UINT32
                                                            | Type::TYPE_UINT64
                                                            | Type::TYPE_BOOL => write!(w, "const auto out = val;")?,
                                                            _ => unreachable!(),
                                                        }
                                                        Ok(())
                                                    })?;

                                                    if let Some(oneof) = field_is_apart_of_union(&field, &oneofs) {
                                                        let union_name = oneof.name();
                                                        match field.runtime_field_type() {
                                                            RuntimeFieldType::Singular(RuntimeType::Enum(..)) => w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(*res);"))?,
                                                            RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(({field_type})out);"))?,
                                                            _ => unreachable!(),
                                                        }
                                                    } else {
                                                        match field.runtime_field_type() {
                                                            RuntimeFieldType::Singular(RuntimeType::Enum(..)) => w.writeln(|w| write!(w, "this->{field_name} = *res;"))?,
                                                            RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->{field_name} = ({field_type})out;"))?,
                                                            RuntimeFieldType::Repeated(RuntimeType::Enum(..)) =>w.writeln(|w| write!(w, "this->{field_name}.push_back(*res);"))?,
                                                            RuntimeFieldType::Repeated(..) => w.writeln(|w| write!(w, "this->{field_name}.push_back(({field_type})out);"))?,
                                                            RuntimeFieldType::Map(..) => todo!(),
                                                        }
                                                    }
                                                    w.writeln(|w| write!(w, "break;"))?;
                                                    Ok(())
                                                },
                                                |w| w.writeln(|w| write!(w, "}}")),
                                            )?;
                                        }
                                        w.writeln(|w| write!(w, "default: return Err<void>(Protobuf::Error::BadVariant);"))?;
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;
                                w.writeln(|w| write!(w, "return Ok<void>();"))?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr std::expected<void, Protobuf::Error> write_64_bit(varint_t val, varint_t field_num) {{")),
                            |w| {
                                let fixed64_fields = get_fields_with_type(&msg, |ty| matches!(ty, Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE));
                                w.write_write_fields(&fixed64_fields, &oneofs)?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr std::expected<void, Protobuf::Error> write_32_bit(varint_t val, varint_t field_num) {{")),
                            |w| {
                                let fixed32_fields = get_fields_with_type(&msg, |ty| matches!(ty, Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT));
                                w.write_write_fields(&fixed32_fields, &oneofs)?;
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr std::expected<void, Protobuf::Error> write_length_delimited(const Protobuf::Buffer& buf, size_t offset, size_t field_len, varint_t field_num, size_t vector_size = 0) {{")),
                            |w| {
                                //length delimited
                                let length_delimited_fields = msg.fields().filter(|field| {
                                    match field.runtime_field_type() {
                                        RuntimeFieldType::Repeated(t) => match t {
                                            RuntimeType::Message(..) | RuntimeType::VecU8 | RuntimeType::String => true,
                                            _ => {
                                                let is_primitive = matches!(
                                                    field.proto().type_(),
                                                    Type::TYPE_DOUBLE
                                                        | Type::TYPE_FLOAT
                                                        | Type::TYPE_INT64
                                                        | Type::TYPE_UINT64
                                                        | Type::TYPE_INT32
                                                        | Type::TYPE_FIXED64
                                                        | Type::TYPE_FIXED32
                                                        | Type::TYPE_BOOL
                                                        | Type::TYPE_UINT32
                                                        | Type::TYPE_SFIXED32
                                                        | Type::TYPE_SFIXED64
                                                        | Type::TYPE_SINT32
                                                        | Type::TYPE_SINT64
                                                        | Type::TYPE_ENUM
                                                );

                                                let is_packed = field.proto().options.get_or_default().packed.unwrap_or(match field.containing_message().file_descriptor().syntax() {
                                                    protobuf::reflect::Syntax::Proto3 => is_primitive,
                                                    _ => false,
                                                });
                                                is_packed
                                            }
                                        },
                                        RuntimeFieldType::Singular(..) => matches!(field.proto().type_(), Type::TYPE_MESSAGE | Type::TYPE_STRING | Type::TYPE_BYTES),
                                        _ => todo!(),
                                    }
                                }).collect::<Vec<_>>();

                                if length_delimited_fields.is_empty() {
                                    w.writeln(|w| write!(w, "return Err<void>(Protobuf::Error::BadVariant);"))?;
                                } else {
                                    w.scoped(
                                        |w| w.writeln(|w| write!(w, "switch (field_num) {{")),
                                        |w| {
                                            for field in length_delimited_fields {
                                                let field_name = field.name();
                                                let field_num = field.number();
                                                let rft = field.runtime_field_type();
                                                let field_type = Self::protobuf_type_to_native_type(
                                                    &rft
                                                );

                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case {field_num}: {{")),
                                                    |w| {
                                                        if let Some(oneof) = field_is_apart_of_union(&field, &oneofs) {
                                                            let union_name = oneof.name();
                                                            match field.runtime_field_type() {
                                                                RuntimeFieldType::Singular(..) => {
                                                                    match field.proto().type_() {
                                                                        Type::TYPE_MESSAGE => {
                                                                            w.writeln(|w| {
                                                                                write!(w, "const auto res = {field_type}")?;

                                                                                let deps = collection_deps.from_field_num(&field.number());

                                                                                let mut deps_iter = deps.iter();

                                                                                if let Some(dep) = deps_iter.next() {
                                                                                    write!(w, "<")?;
                                                                                    let mut c = 0;
                                                                                    w.write_nested_template_field(dep, field_name, &mut c)?;

                                                                                    while let Some(dep) = deps_iter.next() {
                                                                                        let mut c = 0;
                                                                                        w.write_nested_template_field(dep, field_name, &mut c)?;
                                                                                    }
                                                                                    write!(w, ">")?;
                                                                                }
                                                                                write!(w, "::parse_from(buf, offset, offset + field_len);")?;
                                                                                Ok(())
                                                                            })?;
                                                                            w.writeln(|w| write!(w, "check_err(res);"))?;
                                                                            w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(*res);"))?;
                                                                        }
                                                                        Type::TYPE_STRING => {
                                                                            w.writeln(|w| write!(w, "const auto bytes = &buf.read_bytes()[offset];"))?;
                                                                            w.writeln(|w| write!(w, "const auto out = str::new_(bytes, field_len);"))?;
                                                                            w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(out);"))?;
                                                                        }
                                                                        Type::TYPE_BYTES => {
                                                                            w.writeln(|w| write!(w, "const auto bytes = &buf.read_bytes()[offset];"))?;
                                                                            w.writeln(|w| write!(w, "const auto out = bytes::new_(bytes, field_len);"))?;
                                                                            w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(out);"))?;
                                                                        }
                                                                        _ => unreachable!()
                                                                    }
                                                                }
                                                                _ => todo!(),
                                                            }
                                                        } else {
                                                            match field.proto().type_() {
                                                                Type::TYPE_ENUM => {
                                                                    w.writeln(|w| write!(w, "const auto bytes = buf.read_bytes();"))?;
                                                                    w.writeln(|w| write!(w, "size_t idx = offset;"))?;
                                                                    w.scoped(
                                                                        |w| w.writeln(|w| write!(w, "while(idx < offset + field_len) {{")),
                                                                        |w| {
                                                                            w.writeln(|w| write!(w, "const auto varint_res = get_varint(bytes, &idx, offset + field_len);"))?;
                                                                            w.writeln(|w| write!(w, "check_err(varint_res);"))?;

                                                                            let runtime_ty = field.runtime_field_type();
                                                                            let field_ty = Self::protobuf_type_to_native_type(&runtime_ty);
                                                                            w.writeln(|w| write!(w, "const auto enum_res = {field_ty}::parse(*varint_res);"))?;
                                                                            w.writeln(|w| write!(w, "check_err(enum_res);"))?;
                                                                            w.writeln(|w| write!(w, "this->{field_name}.push_back(*enum_res);"))?;
                                                                            Ok(())
                                                                        },
                                                                        |w| w.writeln(|w| write!(w, "}}"))
                                                                    )?;
                                                                }
                                                                Type::TYPE_INT32 | Type::TYPE_INT64 | Type::TYPE_UINT32 | Type::TYPE_UINT64 | Type::TYPE_BOOL | Type::TYPE_SINT32 | Type::TYPE_SINT64 => {
                                                                    w.writeln(|w| write!(w, "const auto bytes = buf.read_bytes();"))?;
                                                                    w.writeln(|w| write!(w, "size_t idx = offset;"))?;
                                                                    w.scoped(
                                                                        |w| w.writeln(|w| write!(w, "while(idx < offset + field_len) {{")),
                                                                        |w| {
                                                                            w.writeln(|w| write!(w, "const auto varint_res = get_varint(bytes, &idx, offset + field_len);"))?;
                                                                            w.writeln(|w| write!(w, "check_err(varint_res);"))?;
                                                                            w.writeln(|w| write!(w, "this->{field_name}.push_back(*varint_res);"))?;
                                                                            Ok(())
                                                                        },
                                                                        |w| w.writeln(|w| write!(w, "}}"))
                                                                    )?;
                                                                }
                                                                Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                                    w.scoped(
                                                                        |w| w.writeln(|w| write!(w, "if (field_len % 4) {{")),
                                                                        |w| w.writeln(|w| write!(w, "return Err<void>(Protobuf::Error::BadLength);")),
                                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                                    )?;
                                                                    w.writeln(|w| write!(w, "const auto len = field_len / 4;"))?;
                                                                    w.writeln(|w| write!(w, "auto idx = offset;"))?;
                                                                    w.writeln(|w| write!(w, "const auto bytes = buf.read_bytes();"))?;

                                                                    w.scoped(
                                                                        |w| w.writeln(|w| write!(w, "for(auto i = 0; i < len; i++) {{")),
                                                                        |w| {
                                                                            w.writeln(|w| write!(w, "const auto item = get_from_bytes<uint32_t>(bytes, idx);"))?;
                                                                            w.writeln(|w| write!(w, "idx += 4;"))?;

                                                                            let rft = field.runtime_field_type();
                                                                            let field_type = Self::protobuf_type_to_native_type(&rft);

                                                                            w.writeln(|w| write!(w, "this->{field_name}.push_back(std::bit_cast<{field_type}>(item));"))?;
                                                                            Ok(())
                                                                        },
                                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                                    )?;
                                                                }
                                                                Type::TYPE_FIXED64 | Type::TYPE_SFIXED64 | Type::TYPE_DOUBLE => {
                                                                    w.scoped(
                                                                        |w| w.writeln(|w| write!(w, "if (field_len % 8) {{")),
                                                                        |w| w.writeln(|w| write!(w, "return Err<void>(Protobuf::Error::BadLength);")),
                                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                                    )?;
                                                                    w.writeln(|w| write!(w, "const auto len = field_len / 8;"))?;
                                                                    w.writeln(|w| write!(w, "auto idx = offset;"))?;
                                                                    w.writeln(|w| write!(w, "const auto bytes = buf.read_bytes();"))?;

                                                                    w.scoped(
                                                                        |w| w.writeln(|w| write!(w, "for(auto i = 0; i < len; i++) {{")),
                                                                        |w| {
                                                                            w.writeln(|w| write!(w, "const auto item = get_from_bytes<uint64_t>(bytes, idx);"))?;
                                                                            w.writeln(|w| write!(w, "idx += 8;"))?;

                                                                            let rft = field.runtime_field_type();
                                                                            let field_type = Self::protobuf_type_to_native_type(&rft);

                                                                            w.writeln(|w| write!(w, "this->{field_name}.push_back(std::bit_cast<{field_type}>(item));"))?;
                                                                            Ok(())
                                                                        },
                                                                        |w| w.writeln(|w| write!(w, "}}")),
                                                                    )?;
                                                                }
                                                                Type::TYPE_MESSAGE => {
                                                                    let rft = field.runtime_field_type();
                                                                    let field_type = Self::protobuf_type_to_native_type(
                                                                        &rft
                                                                    );
                                                                    let field_name = field.name();

                                                                    match field.runtime_field_type() {
                                                                        RuntimeFieldType::Singular(..) => {
                                                                            w.writeln(|w| {
                                                                                write!(w, "const auto res = {field_type}")?;

                                                                                let deps = collection_deps.from_field_num(&field.number());

                                                                                let mut deps_iter = deps.iter();

                                                                                if let Some(dep) = deps_iter.next() {
                                                                                    write!(w, "<")?;
                                                                                    let mut c = 0;
                                                                                    w.write_nested_template_field(dep, field_name, &mut c)?;

                                                                                    while let Some(dep) = deps_iter.next() {
                                                                                        let mut c = 0;
                                                                                        w.write_nested_template_field(dep, field_name, &mut c)?;
                                                                                    }
                                                                                    write!(w, ">")?;
                                                                                }
                                                                                write!(w, "::parse_from(buf, offset, offset + field_len);")?;
                                                                                Ok(())
                                                                            })?;
                                                                        }
                                                                        RuntimeFieldType::Repeated(..) => {
                                                                            w.writeln(|w| {
                                                                                write!(w, "const auto res = {field_type}")?;

                                                                                let deps = collection_deps.from_field_num(&field.number());

                                                                                let mut deps_iter = deps.iter();

                                                                                let first = deps_iter.next().unwrap();

                                                                                let mut first_dep_iter = first.deps();

                                                                                if let Some(fd) = first_dep_iter.next() {
                                                                                    write!(w, "<")?;
                                                                                    let mut c = 0;
                                                                                    w.write_nested_template_field(fd, field_name, &mut c)?;

                                                                                    while let Some(fd) = first_dep_iter.next() {
                                                                                        let mut c = 0;
                                                                                        w.write_nested_template_field(fd, field_name, &mut c)?;
                                                                                    }
                                                                                    write!(w, ">")?;
                                                                                }
                                                                                write!(w, "::parse_from(buf, offset, offset + field_len);")?;
                                                                                Ok(())
                                                                            })?;
                                                                        }
                                                                        RuntimeFieldType::Map(..) => todo!(),
                                                                    }

                                                                    w.writeln(|w| write!(w, "check_err(res);"))?;
                                                                    match field.runtime_field_type() {
                                                                        RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->{field_name} = *res;"))?,
                                                                        RuntimeFieldType::Repeated(..) => w.writeln(|w| write!(w, "this->{field_name}.push_back(*res);"))?,
                                                                        RuntimeFieldType::Map(..) => todo!(),
                                                                    }
                                                                }
                                                                Type::TYPE_STRING => {
                                                                    match field.runtime_field_type() {
                                                                        RuntimeFieldType::Singular(..) => {
                                                                            w.writeln(|w| write!(w, "const auto bytes = &buf.read_bytes()[offset];"))?;
                                                                            w.writeln(|w| write!(w, "this->{field_name} = str::new_(bytes, field_len);"))?;
                                                                        }
                                                                        RuntimeFieldType::Repeated(..) => {
                                                                            w.writeln(|w| write!(w, "const auto bytes = buf.read_bytes();"))?;
                                                                            w.writeln(|w| write!(w, "const auto field = str::new_(bytes, field_len);"))?;
                                                                            w.writeln(|w| write!(w, "this->{field_name}.push_back(field);"))?;
                                                                        }
                                                                        RuntimeFieldType::Map(..) => todo!(),
                                                                    }
                                                                }
                                                                Type::TYPE_BYTES => {
                                                                    match field.runtime_field_type() {
                                                                        RuntimeFieldType::Singular(..) => {
                                                                            w.writeln(|w| write!(w, "const auto bytes = &buf.read_bytes()[offset];"))?;
                                                                            w.writeln(|w| write!(w, "this->{field_name} = bytes::new_(bytes, field_len);"))?;
                                                                        }
                                                                        RuntimeFieldType::Repeated(..) => {
                                                                            w.writeln(|w| write!(w, "const auto bytes = buf.read_bytes();"))?;
                                                                            w.writeln(|w| write!(w, "const auto field = bytes::new_(bytes, field_len);"))?;
                                                                            w.writeln(|w| write!(w, "this->{field_name}.push_back(field);"))?;
                                                                        }
                                                                        RuntimeFieldType::Map(..) => todo!(),
                                                                    }
                                                                }
                                                                _ => unreachable!(),
                                                            }
                                                        }
                                                        w.writeln(|w| write!(w, "break;"))?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                )?;

                                            }
                                            w.writeln(|w| write!(w, "default: return Err<void>(Protobuf::Error::BadVariant);"))?;
                                            Ok(())
                                        },
                                        |w| w.writeln(|w| write!(w, "}}")),
                                    )?;
                                    w.writeln(|w| write!(w, "return Ok<void>();"))?;
                                }
                                Ok(())
                            },
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr static std::expected<{msg_name}, Protobuf::Error> parse_from(const Protobuf::Buffer& buf) {{")),
                            |w| w.writeln(|w| write!(w, "return {msg_name}::parse_from(buf, 0, buf.read_len());")),
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr static std::expected<{msg_name}, Protobuf::Error> parse_from(const Protobuf::Buffer& buf, size_t start, size_t len) {{")),
                            |w| w.writeln(|w| write!(w, "return parse_from_<{msg_name}>(buf, start, len);")),
                            |w| w.writeln(|w| write!(w, "}}")),
                        )?;
                        Ok(())
                    },
                    |_| Ok(())
                )?;
                Ok(())
            },
            |w| w.writeln(|w| write!(w, "}};"))
        )?;

        if let Some(ReflectionTests{tests_per_struct: test_count, buffer_size, max_len}) = self.options.reflection_tests {
            if collection_deps.collection_deps().count() > 0 {
                self.writeln(|w| {
                    write!(w, "template <")?;

                    let mut first = true;
                    let mut c = 0;
                    for (field_num, deps) in collection_deps.deps_by_field_num() {
                        let field = msg.field_by_number(*field_num as u32).unwrap();
                        let name = field.name();
                        for ty in deps {
                            w.write_nested_template(ty, &mut c, name, &mut first, false, true)?;
                        }
                        c = 0;
                    }
                    write!(w, ">")?;
                    Ok(())
                })?;
            }





            self.scoped(
                |w| w.writeln(|w| {
                    write!(w, "constexpr bool {msg_name}")?;

                    if collection_deps.collection_deps().count() > 0 {
                        write!(w, "<")?;

                        let mut first = true;
                        let mut c = 0;
                        for (field_num, deps) in collection_deps.deps_by_field_num() {
                            let field = msg.field_by_number(*field_num as u32).unwrap();
                            let name = field.name();
                            for ty in deps {
                                w.write_nested_template(ty, &mut c, name, &mut first, false, false)?;
                            }
                            c = 0;
                        }
                        write!(w, ">")?;
                    }

                    write!(w, "::reflection_test() {{")?;
                    Ok(())
                }),
                |w| {
                    w.writeln(|w| write!(w, "Protobuf::SizedBuffer<{buffer_size}> buf;"))?;
                    w.writeln(|w| write!(w, "{msg_name} gen;"))?;
                    w.scoped(
                        |w| w.writeln(|w| write!(w, "for(uint64_t i = 0; i < {test_count}; i++) {{")),
                        |w| {
                            w.writeln(|w| write!(w, "buf.clear_written();"))?;
                            w.writeln(|w| write!(w, "buf.clear_read();"))?;
                            w.writeln(|w| write!(w, "gen = {msg_name}::generate_random();"))?;
                            w.writeln(|w| write!(w, "const auto res = gen.write_to(buf);"))?;
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "if (!res) {{")),
                                |w| {
                                    w.writeln(|w| write!(w, "gen.free_generated_data();"))?;
                                    w.writeln(|w| write!(w, "return false;"))?;
                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;
                            w.writeln(|w| write!(w, "auto read_buf = buf.read_bytes_mut();"))?;
                            w.writeln(|w| write!(w, "const auto& [write_buf, write_len] = buf.write_buf();"))?;
                            w.writeln(|w| write!(w, "copy_buffer(read_buf, write_buf, write_len);"))?;
                            w.writeln(|w| write!(w, "buf.set_read_len(write_len);"))?;

                            w.writeln(|w| write!(w, "const auto reflect = {msg_name}::parse_from(buf);"))?;
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "if (!reflect) {{")),
                                |w| {
                                    w.writeln(|w| write!(w, "gen.free_generated_data();"))?;
                                    w.writeln(|w| write!(w, "return false;"))?;
                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;

                            w.scoped(
                                |w| w.writeln(|w| write!(w, "if (*reflect != gen) {{")),
                                |w| {
                                    w.writeln(|w| write!(w, "gen.free_generated_data();"))?;
                                    w.writeln(|w| write!(w, "return false;"))?;
                                    Ok(())
                                },
                                |w| w.writeln(|w| write!(w, "}}")),
                            )?;

                            w.writeln(|w| write!(w, "gen.free_generated_data();"))?;
                            
                            Ok(())
                        },
                        |w| w.writeln(|w| write!(w, "}}")),
                     )?;
                    w.writeln(|w| write!(w, "return true;"))?;
                    Ok(())
                },
                |w| w.writeln(|w| write!(w, "}}")),
            )?;

            self.writeln(|w| {
                write!(w, "static_assert({msg_name}")?;
                if collection_deps.collection_deps().count() > 0 {
                    write!(w, "<")?;
                    let mut first = true;
                    for (field_num, deps) in collection_deps.deps_by_field_num() {
                        for ty in deps {
                            w.write_template_default(ty, &mut first, true)?;
                        }
                    }
                    write!(w, ">")?;


                }
                write!(w, "::reflection_test(), \"`{msg_name}` did not pass reflection tests\");")?;
                Ok(())
            })?;
        }
        Ok(())
    }

    fn write_service(&mut self, _: &FileDescriptor, _: &ServiceDescriptor) -> std::io::Result<()> {
        Ok(())
    }

    fn protobuf_type_to_native_type(
        protobuf_type: &RuntimeFieldType
    ) -> &str {
        match protobuf_type {
            RuntimeFieldType::Singular(ty) | RuntimeFieldType::Repeated(ty) => {
                str_from_runtime_type(ty)
            }
            _ => todo!(),
        }
    }
}

fn str_from_runtime_type(rty: &RuntimeType) -> &str {
    match rty {
        RuntimeType::I32 => "int32_t",
        RuntimeType::I64 => "int64_t",
        RuntimeType::U32 => "uint32_t",
        RuntimeType::U64 => "uint64_t",
        RuntimeType::F32 => "float",
        RuntimeType::F64 => "double",
        RuntimeType::Bool => "bool",
        RuntimeType::String => "str",
        RuntimeType::VecU8 => "Bytes",
        RuntimeType::Enum(e) => e.name(),
        RuntimeType::Message(m) => m.name(),
    }
}

fn generate_random_field(writer: &mut CppWriter, field: &FieldDescriptor, collection_deps: &CollectionDeps) -> std::io::Result<()> {
    let field_name = field.name();

    use crate::ProtobufBindingsWriter;
    let ft = field.runtime_field_type();
    let field_type = CppWriter::protobuf_type_to_native_type(&ft);

    let field_num = field.number();

    let is_alloc_dependent = field.proto().type_() == Type::TYPE_MESSAGE && collection_deps.from_field_num(&field_num).len() > 0;

    if field.proto().proto3_optional() {
        if is_alloc_dependent {
            writer.writeln(|w| {
                write!(w, "std::optional<{field_type}<")?;
                let deps = collection_deps.from_field_num(&field.number());
                let field_name = field.name();

                let mut first = true;
                let mut c = 0;

                for ty in deps {
                    w.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                }
                write!(w, ">> rand_{field_name};")?;
                Ok(())
            })?;
        } else {
            writer.writeln(|w| write!(w, "std::optional<{field_type}> rand_{field_name};"))?;
        }
    } else {
        let should_assign = matches!(field.runtime_field_type(), RuntimeFieldType::Repeated(..)) || matches!(field.proto().type_(), Type::TYPE_BYTES | Type::TYPE_STRING);

        if !should_assign {
            if is_alloc_dependent {
                writer.writeln(|w| {
                    write!(w, "{field_type}<")?;
                    let deps = collection_deps.from_field_num(&field.number());
                    let field_name = field.name();

                    let mut first = true;
                    let mut c = 0;

                    for ty in deps {
                        w.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                    }
                    write!(w, "> rand_{field_name};")?;
                    Ok(())
                })?;
            } else {
                writer.writeln(|w| write!(w, "{field_type} rand_{field_name};"))?;
            }
        }
    }

    match field.runtime_field_type() {
        RuntimeFieldType::Singular(s) => {
            if field.proto().proto3_optional() {
                writer.writeln(|w| write!(w, "PCG<uint8_t> rand_optional_{field_name};"))?;
                writer.writeln(|w| write!(w, "const auto some_{field_name} = rand_optional_{field_name}() & 0x01;"))?;
                writer.writeln(|w| write!(w, "if (some_{field_name}) {{"))?;
                writer.increment_tab();
            }
            match s {
                RuntimeType::VecU8 => {
                    writer.writeln(|w| write!(w, "const auto& [bytes_{field_name}, len_{field_name}] = generate_random_bytes();"))?;
                    writer.writeln(|w| write!(w, "out.{field_name} = bytes::new_(bytes_{field_name}, len_{field_name});"))?;
                }
                RuntimeType::String => {
                    writer.writeln(|w| write!(w, "const auto& [bytes_{field_name}, len_{field_name}] = generate_random_bytes();"))?;
                    writer.writeln(|w| write!(w, "out.{field_name} = str::new_(bytes_{field_name}, len_{field_name});"))?;
                }
                RuntimeType::Message(msg) => {
                    let msg_name = msg.name();

                    if is_alloc_dependent {
                        writer.writeln(|w| {
                            write!(w, "rand_{field_name} = {msg_name}<")?;
                            let deps = collection_deps.from_field_num(&field.number());
                            let mut first = true;
                            let mut c = 0;

                            for ty in deps {
                                w.write_nested_template(ty, &mut c, field_name, &mut first, false, false)?;
                            }
                            write!(w, ">::generate_random();")?;

                            Ok(())
                        })?;
                    } else {
                        writer.writeln(|w| write!(w, "rand_{field_name} = {msg_name}::generate_random();"))?;
                    }
                }
                RuntimeType::Enum(e) => {
                    let enum_name = e.name();
                    writer.writeln(|w| write!(w, "rand_{field_name} = {enum_name}::generate_random();"))?;
                }
                RuntimeType::U32 => {
                    writer.writeln(|w| write!(w, "PCG<uint32_t> gen_rand_{field_name};"))?;
                    writer.writeln(|w| write!(w, "rand_{field_name} = gen_rand_{field_name}();"))?;
                }
                RuntimeType::U64 => {
                    writer.writeln(|w| write!(w, "PCG<uint64_t> gen_rand_{field_name};"))?;
                    writer.writeln(|w| write!(w, "rand_{field_name} = gen_rand_{field_name}();"))?;
                }
                RuntimeType::I32 => {
                    writer.writeln(|w| write!(w, "PCG<int32_t> gen_rand_{field_name};"))?;
                    writer.writeln(|w| write!(w, "rand_{field_name} = gen_rand_{field_name}();"))?;
                }
                RuntimeType::I64 => {
                    writer.writeln(|w| write!(w, "PCG<int64_t> gen_rand_{field_name};"))?;
                    writer.writeln(|w| write!(w, "rand_{field_name} = gen_rand_{field_name}();"))?;
                }
                RuntimeType::F32 => {
                    writer.writeln(|w| write!(w, "PCG<float32_t> gen_rand_{field_name};"))?;
                    writer.writeln(|w| write!(w, "rand_{field_name} = gen_rand_{field_name}();"))?;
                }
                RuntimeType::F64 => {
                    writer.writeln(|w| write!(w, "PCG<float64_t> gen_rand_{field_name};"))?;
                    writer.writeln(|w| write!(w, "rand_{field_name} = gen_rand_{field_name}();"))?;
                }
                RuntimeType::Bool => {
                    writer.writeln(|w| write!(w, "PCG<bool> gen_rand_{field_name};"))?;
                    writer.writeln(|w| write!(w, "rand_{field_name} = distr_{field_name}(random_gen) & 1;"))?;
                }
            }
            if field.proto().proto3_optional() {
                writer.decrement_tab();
                writer.writeln(|w| write!(w, "}} else {{"))?;
                writer.increment_tab();
                writer.writeln(|w| write!(w, "rand_{field_name} = std::nullopt;"))?;
                writer.decrement_tab();
                writer.writeln(|w| write!(w, "}}"))?;
            }
        }
        RuntimeFieldType::Repeated(r) => {
            writer.writeln(|w| write!(w, "PCG<size_t> gen_rand_{field_name}_len;"))?;
            writer.writeln(|w| write!(w, "const auto {field_name}_len = gen_rand_{field_name}_len();"))?;

            let max_len = writer.options.reflection_tests.as_ref().map(|test| test.max_len).unwrap_or(1024) - 1;
            writer.writeln(|w| write!(w, "const auto masked_{field_name}_len = {field_name}_len & {max_len};"))?;
            let ty = str_from_runtime_type(&r);

            if matches!(r, RuntimeType::U32 | RuntimeType::U64 | RuntimeType::I32 | RuntimeType::I64| RuntimeType::F32 | RuntimeType::F64 | RuntimeType::Bool) {
                writer.writeln(|w| write!(w, "PCG<{ty}> gen_rand_{field_name};"))?;
            }

            writer.scoped(
                |w| w.writeln(|w| write!(w, "for(auto i = 0; i < masked_{field_name}_len; i++) {{")),
                |w| {
                    match r {
                        RuntimeType::String => {
                            w.writeln(|w| write!(w, "const auto& [bytes, len] = generate_random_bytes();"))?;
                            w.writeln(|w| write!(w, "const auto item = str::new_(bytes, len);"))?;
                        },
                        RuntimeType::VecU8 => w.writeln(|w| write!(w, "const auto item = generate_random_bytes();"))?,
                        RuntimeType::Message(m) => {
                            let msg_name = m.name();

                            w.writeln(|w| {
                                write!(w, "const auto item = {msg_name}")?;

                                if let Some(dep_count) = collection_deps.from_field_num(&field_num).get(0).map(|d| d.deps().count()) {
                                    if dep_count > 0 {
                                        write!(w, "<>")?;
                                    }
                                }

                                write!(w, "::generate_random();")?;

                                Ok(())
                            })?;
                        },
                        RuntimeType::Enum(e) => {
                            let enum_name = e.name();
                            w.writeln(|w| write!(w, "const auto item = {enum_name}::generate_random();"))?;
                        },
                        _ => {
                            w.writeln(|w| write!(w, "const auto item = gen_rand_{field_name}();"))?;
                        }
                    }

                    w.writeln(|w| write!(w, "out.{field_name}.push_back(item);"))?;
                    Ok(())
                },
                |w| w.writeln(|w| write!(w, "}}"))
             )?;
        }
        RuntimeFieldType::Map(..) => todo!(),
    }
    Ok(())
}

fn get_fields_with_type(msg_desc: &MessageDescriptor, mut f: impl FnMut(Type) -> bool) -> Vec<FieldDescriptor> {
    msg_desc.fields().filter(|field| f(field.proto().type_())).collect::<Vec<_>>()
}

fn field_is_apart_of_union<'a>(field: &FieldDescriptor, unions: &'a [OneofDescriptor]) -> Option<&'a OneofDescriptor> {
    for oneof in unions {
        for union_field in oneof.fields() {
            if union_field.number() == field.number() {
                return Some(oneof);
            }
        }
    }
    return None;
}
