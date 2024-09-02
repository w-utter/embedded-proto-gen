use protobuf::reflect::{FileDescriptor, EnumDescriptor, MessageDescriptor, ServiceDescriptor, OneofDescriptor, FieldDescriptor};
use protobuf::reflect::RuntimeType;

use crate::CollectionDependencies as CollectionDeps;
use crate::ProtobufType;

#[derive(Default)]
pub struct CppWriter {
    inner: Vec<u8>,
    tab_indent: usize,
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
        let bit_size = oneof.fields().count().next_power_of_two().ilog2();
        let aligned_bit_size = ((bit_size + 7) / 8) * 8;
        let union_name = oneof.name();
        self.scoped(
            |w| w.writeln(|w| write!(w, "typedef union {union_name}_t {{")),
            |w| {
                w.writeln(|w| write!(w, "bool dummy {{false}};"))?;
                for variant in oneof.fields() {
                    let deps = collection_deps.from_field_num(&variant.number());
                    w.write_field(&variant, deps)?;
                }
                w.writeln(|w| write!(w, "constexpr {union_name}_t() {{}}"))?;
                w.writeln(|w| write!(w, "constexpr ~{union_name}_t() {{}}"))?;
                Ok(())
            },
            |w| w.writeln(|w| write!(w, "}} {union_name}_t;")),
        )?;
        //FIXME(for oneofs): need an additional variant for when there is nothing set (default variant)
        self.writeln(|w| write!(w, "uint{aligned_bit_size}_t {union_name}_variant;"))?;
        self.writeln(|w| write!(w, "{union_name}_t {union_name}_storage;"))?;
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

                                if let Some(oneof) = field_is_apart_of_union(&field, oneofs) {
                                    let union_name = oneof.name();
                                    match field.runtime_field_type() {
                                        RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(({field_type})val);"))?,
                                        RuntimeFieldType::Repeated(..) | RuntimeFieldType::Map(..) => todo!(),
                                    }
                                } else {
                                    match field.runtime_field_type() {
                                        RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->{field_name} = ({field_type})val;"))?,
                                        RuntimeFieldType::Repeated(..) => w.writeln(|w| write!(w, "this->{field_name}.push_back(({field_type})val);"))?,
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
    
    fn write_field(&mut self, field: &FieldDescriptor, deps: &[ProtobufType]) -> std::io::Result<()> {
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
                    write!(w, " {field_name};")?;
                    Ok(())
                })?;
            }
            RuntimeFieldType::Repeated(..) => {
                self.writeln(|w| {
                    write!(w, "std::vector<{field_type}")?;

                    let mut deps_iter = deps.iter();

                    let first = deps_iter.next().unwrap();

                    let mut first_dep_iter = first.deps();

                    if let Some(fd) = first_dep_iter.next() {
                        write!(w, "<")?;
                        let mut c = 1;
                        w.write_nested_template_field(fd, field_name, &mut c)?;
                        while let Some(fd) = first_dep_iter.next() {
                            let mut c = 1;
                            w.write_nested_template_field(fd, field_name, &mut c)?;
                        }
                        write!(w, ">")?;
                    }

                    write!(w, ", alloc_{field_name}_0> ")?;
                    write!(w, "{field_name};")?;
                    Ok(())
                })?;
            },
            RuntimeFieldType::Map(..) => todo!(),
        }
        Ok(())
    }

    fn write_nested_template(&mut self, tys: &ProtobufType, c: &mut usize, field_name: &str, first: &mut bool, write_default: bool) -> std::io::Result<()> {
        for ty in tys.deps() {
            self.write_nested_template(ty, c, field_name, first, write_default)?;
        }
        match tys.field_type() {
            RuntimeFieldType::Repeated(..) => {
                let ty = str_from_runtime_type(tys.runtime_type());
                if !*first {
                    write!(self, ", ")?;
                } else {
                    *first = false;
                }
                if write_default {
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
                        self.write_nested_template(ty, &mut c, field_name, &mut first, false)?;
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
                if write_default {
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
                        self.write_nested_template(ty, &mut c, field_name, &mut first, false)?;
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
        self.write_nested_template(tys, c, field_name, &mut first, false)?;
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
    fn writer(&mut self) -> &mut impl std::io::Write {
        self
    }

    fn write_prelude(&mut self) -> std::io::Result<()> {
        writeln!(
            self,
            r#"#include <stdint.h>
#include <stddef.h>
#include <string>
#include <expected>
#include <vector>
#include <tuple>
#include <optional>
#include <type_traits>
#include <memory>

#include <cmath>

#define TAG_TYPE_BITS 3
#define TAG_TYPE_MASK (1 << TAG_TYPE_BITS) - 1
#define MAX_FIELD_NUM ((2 << 29) - 1)

#define check_err(res) check_err_with_ret(void, res)

#define check_err_with_ret(ty, res) if (!res) {{ return Err<ty>(res.error()); }}

typedef uint32_t varint_t;

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
            /// used for read buffer
            virtual void set_bytes(uint8_t* bytes) = 0;
            /// used for write buffer
            virtual void write_bytes(const uint8_t* bytes, size_t len) = 0;

            Buffer() {{}}
            virtual ~Buffer() = 0;
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
            virtual size_t buffer_size() const = 0;
            virtual const uint8_t* written_bytes() const = 0;
            virtual uint8_t* written_bytes_mut() = 0;
            virtual size_t written_len() const = 0;
            virtual const uint8_t* read_bytes() const = 0;
            virtual size_t read_len() const = 0;
            ///NOTE: copying is not done here.
            constexpr void set_read_data(uint8_t* bytes, size_t len) {{
                this->set_bytes(bytes);
                this->set_read_len(len);
            }}

            constexpr void set_write_data(const uint8_t* bytes, size_t len) {{
                this->write_bytes(bytes, len);
            }}

            constexpr const std::tuple<const uint8_t*, size_t> read_buf() const {{
                const std::tuple<const uint8_t*, size_t> out = {{this->read_bytes(), this->read_len()}};
                return out;
            }}

            constexpr const std::tuple<const uint8_t*, size_t> write_buf() const {{
                const std::tuple<const uint8_t*, size_t> out = {{this->written_bytes(), this->written_len()}};
                return out;
            }}

            constexpr const std::tuple<uint8_t*, size_t> write_buf_mut() {{
                const std::tuple<uint8_t*, size_t> out = {{this->written_bytes_mut(), this->written_len()}};
                return out;
            }}

            constexpr std::expected<void, Error> write_varint(varint_t varint) {{
              auto size = varint < 2 ? 1 : (std::log2(varint) + 6) / 7;
              const auto& [bytes, len] = this->write_buf_mut();
              if(len + size > this->buffer_size()) {{
                return std::unexpected(Error::BufferOOM);
              }}
              auto idx = 0;
              while(varint > 0x80) {{
                bytes[len + idx] = ((uint8_t)varint) | 0x80;
                varint >>= 7;
                idx += 1;
              }}

              bytes[len + idx] = ((uint8_t)varint);
              this->set_write_len(len + size);
              const std::expected<void, Error> out;
              return out;
            }}

            constexpr std::expected<void, Error> write_tag(varint_t field_num, uint8_t tag_kind) {{
                if(field_num > MAX_FIELD_NUM) {{
                    return std::unexpected(Error::BadVariant);
                }}
                return this->write_varint((((varint_t)tag_kind) << TAG_TYPE_BITS) | tag_kind);
            }}

            constexpr std::expected<void, Error> write_length_delimited(varint_t len, const void* data) {{
                const auto res = this->write_varint(len);
                if(!res) {{
                    return std::unexpected(res.error());
                }}
                const auto& [write_buf, write_len] = this->write_buf_mut();
                if (write_len + len > this->buffer_size()) {{
                    return std::unexpected(Error::BufferOOM);
                }}

                memcpy(&write_buf[write_len], data, len);
                this->set_write_len(this->written_len() + write_len);
                const std::expected<void, Error> out;
                return out;
            }}

            constexpr std::expected<void, Error> write_32_bit(uint32_t bits) {{
                const auto& [write_buf, write_len] = this->write_buf_mut();
                if(write_len + 4 > this->buffer_size()) {{
                    return std::unexpected(Error::BufferOOM);
                }}
                memcpy(&write_buf[write_len], &bits, 4);
                this->set_write_len(write_len + 4);
                const std::expected<void, Error> out;
                return out;
            }}

            constexpr std::expected<void, Error> write_64_bit(uint64_t bits) {{
                const auto& [write_buf, write_len] = this->write_buf_mut();
                if(write_len + 8 > this->buffer_size()) {{
                    return std::unexpected(Error::BufferOOM);
                }}
                memcpy(&write_buf[write_len], &bits, 8);
                this->set_write_len(write_len + 8);
                const std::expected<void, Error> out;
                return out;
            }}
    }};

    template <size_t W_SIZE>
    class SizedBuffer: public Buffer {{
        size_t write_len = 0;
        uint8_t write_buffer[W_SIZE];
        size_t r_len = 0;
        /// flexible array member
        const uint8_t read_buffer[];
        public:
            constexpr void set_write_len(size_t len) override {{
                this->write_len = len;
            }}
            constexpr void set_read_len(size_t len) override {{
                this->r_len = len;
            }}
            ///NOTE: copying is not done here.
            constexpr void set_bytes(uint8_t* bytes) override {{
                this->read_buffer = (const uint8_t*)bytes;
            }}
            constexpr void write_bytes(const uint8_t* bytes, size_t len) override {{
                memcpy(this->write_buffer, bytes, len);
                this->set_write_len(len);
            }}
            constexpr SizedBuffer() = default;
            ~SizedBuffer() override = default;

            constexpr size_t buffer_size() const override {{
                return W_SIZE;
            }}

            constexpr const uint8_t* written_bytes() const override {{
                return this->write_buffer;
            }}

            constexpr uint8_t* written_bytes_mut() override {{
                return this->write_buffer;
            }}

            constexpr size_t written_len() const override {{
                return this->write_len;
            }}

            constexpr const uint8_t* read_bytes() const override {{
                return this->read_buffer;
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

constexpr std::expected<size_t, Protobuf::Error> get_varint(const uint8_t* bytes, size_t* index, size_t len) {{
    auto pos = 0;
    auto out = 0;
    auto valid = false;

    for(auto i = 0; i < len - *index; i++) {{
        const auto idx = *index + i;
        const auto byte = bytes[idx];
        if(!(byte & 0x80)) {{
            *index = idx;
            pos = i + 1;
            valid = true;
            break;
        }}
        out += ((varint_t)bytes[idx]) << (0x7 * i);
    }}
    if(!valid) {{
        return Err<size_t>(Protobuf::Error::BadMetadata);
    }}
    return Ok(out);
}}

constexpr std::expected<std::tuple<uint8_t, uint8_t>, Protobuf::Error> get_wire_format(const uint8_t* bytes, size_t* index, size_t len) {{
    const auto first_byte = bytes[*index];
    const auto wire_kind = first_byte & 0x7;
    if(first_byte & 0x80) {{
        const auto field_num = first_byte >> 3;
        *index += 1;
        const std::tuple<uint8_t, uint8_t> out = {{field_num, wire_kind}};
        return Ok(out);
    }}

    auto pos = 0;
    auto field_num = 0;
    auto valid = false;

    for(auto i = 0; i < len - *index; i++) {{
        const auto idx = *index + i;
        const auto byte = bytes[idx];
        field_num += (byte & 0x7) << (0x7 * i);
        if(!(byte & 0x80)) {{
            *index = idx + 1;
            valid = true;
            break;
        }}
    }}

    if(!valid) {{
        return Err<std::tuple<uint8_t, uint8_t>>(Protobuf::Error::BadMetadata);
    }}

    const std::tuple<uint8_t, uint8_t> out = {{field_num >> 3, wire_kind}};
    return Ok(out);
}}"#
        )
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
        Ok(())
    }

    fn write_enum(&mut self, _: &FileDescriptor, enm: &EnumDescriptor) -> std::io::Result<()> {
        let enum_name = enm.full_name();

        let bit_size = enm.values().count().next_power_of_two().ilog2();
        let aligned_bit_size = ((bit_size + 7) / 8) * 8;
        self.scoped(
            |w| w.writeln(|w| write!(w, "enum class {enum_name}_t : uint{aligned_bit_size}_t {{")),
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

        self.scoped(
            |w| w.writeln(|w| write!(w, "class {enum_name} {{")),
            |w| {
                w.writeln(|w| write!(w, "{enum_name}_t inner;"))?;
                w.newline()?;
                w.scoped(
                |w| w.writeln(|w| write!(w, "public:")),
                |w| {

                    let default_val = enm.default_value();
                    let default_variant = default_val.name();
                    w.writeln(|w| write!(w, "constexpr {enum_name}() {{ this->inner = {enum_name}_t::{default_variant}; }}"))?;
                    w.writeln(|w| write!(w, "constexpr {enum_name}({enum_name}_t variant) {{ this->inner = variant; }}"))?;
                    w.writeln(|w| write!(w, "constexpr ~{enum_name}() = default;"))?;
                    w.newline()?;
                    w.writeln(|w| write!(w, "constexpr operator const {enum_name}_t() const {{ return inner; }}"))?;
                    w.writeln(|w| write!(w, "explicit operator bool() const = delete;"))?;
                    w.writeln(|w| write!(w, "constexpr bool operator == ({enum_name} rhs) const {{ return this->inner == rhs.inner; }}"))?;
                    w.writeln(|w| write!(w, "constexpr bool operator != ({enum_name} rhs) const {{ return this->inner != rhs.inner; }}"))?;
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
                            w.writeln(|w| write!(w, "varint_t varint;"))?;
                            w.newline()?;
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "switch (this->inner) {{")),
                                |w| {
                                    for variant in enm.values() {
                                        let variant_name = variant.name();
                                        let variant_num = variant.value();
                                        w.scoped(
                                            |w| w.writeln(|w| write!(w, "case {enum_name}_t::{variant_name}: {{")),
                                            |w| {
                                                w.writeln(|w| write!(w, "varint = {variant_num};"))?;
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
                            w.writeln(|w| write!(w, "return buf.write_varint(varint);"))?;
                            Ok(())
                        },
                        |w| w.writeln(|w| write!(w, "}}")),
                    )?;
                    Ok(())
                },
                |_| Ok(()),
            )
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
                        w.write_nested_template(alloc, &mut c, field_name, &mut first, true)?;

                        while let Some(alloc) = alloc_iter.next() {
                            write!(w, ", ")?;
                            let mut c = 0;
                            let mut first = true;
                            w.write_nested_template(alloc, &mut c, field_name, &mut first, true)?;
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
                            w.write_nested_template(alloc, &mut c, field_name, &mut first, true)?;

                            while let Some(alloc) = alloc_iter.next() {
                                write!(w, ", ")?;
                                let mut c = 0;
                                let mut first = true;
                                w.write_nested_template(alloc, &mut c, field_name, &mut first, true)?;
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
                        for field in &fields {
                            let deps = collection_deps.from_field_num(&field.number());
                            w.write_field(&field, deps)?;
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


                        let needs_explicit_drop = oneofs.iter().any(|oneof| oneof.fields().any(|field| matches!(field.proto().type_(), Type::TYPE_STRING | Type::TYPE_BYTES | Type::TYPE_MESSAGE)));
                        if needs_explicit_drop {
                            w.scoped(
                                |w| w.writeln(|w| write!(w, "constexpr ~{msg_name}() {{")),
                                |w| {
                                    for oneof in &oneofs {
                                        let explicit_drop_variants = oneof.fields().filter(|variant| matches!(variant.proto().type_(), Type::TYPE_STRING | Type::TYPE_BYTES | Type::TYPE_MESSAGE)).collect::<Vec<_>>();
                                        if !explicit_drop_variants.is_empty() {
                                            let union_name = oneof.name();
                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "switch (this->{union_name}_variant) {{")),
                                                |w| {
                                                    for variant in explicit_drop_variants {
                                                        let variant_num = variant.number();
                                                        let variant_name = variant.name();
                                                        let rft = variant.runtime_field_type();

                                                        let variant_type = Self::protobuf_type_to_native_type( &rft                                                        );
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "case {variant_num}: {{")),
                                                            |w| {
                                                                w.scoped(
                                                                    |w| w.writeln(|w| write!(w, "if (!std::is_trivially_destructible<{variant_type}>::value) {{")),
                                                                    |w| w.writeln(|w| write!(w, "std::destroy_at(&(this->{union_name}_storage.{variant_name}));")),
                                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                                )?;
                                                                w.writeln(|w| write!(w, "break;"))?;
                                                                Ok(())
                                                            },
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?
                                                    }
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
                                                for variant in oneof.fields() {
                                                    let variant_num = variant.number();
                                                    let variant_name = variant.name();
                                                    w.scoped(
                                                        |w| w.writeln(|w| write!(w, "case {variant_num}: {{")),
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
                            for variant in oneof.fields() {
                                let variant_num = variant.number();
                                let variant_name = variant.name();
                                let rft = variant.runtime_field_type();
                                let variant_type = Self::protobuf_type_to_native_type(
                                    &rft
                                );
                                w.scoped(
                                    |w| w.writeln(|w| write!(w, "constexpr std::optional<{variant_type}> {union_name}_as_{variant_name}() const {{")),
                                    |w| {
                                        w.scoped(
                                            |w| w.writeln(|w| write!(w, "if (this->{union_name}_variant == {variant_num}) {{")),
                                            |w| w.writeln(|w| write!(w, "return this->{union_name}_storage.{variant_name};")),
                                            |w| w.writeln(|w| write!(w, "}}")),
                                        )?;
                                        w.writeln(|w| write!(w, "return std::nullopt;"))?;
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;
                                w.scoped(
                                    |w| w.writeln(|w| write!(w, "constexpr void set_{union_name}_to_{variant_name}({variant_type} {variant_name}) {{")),
                                    |w| {
                                        let explicit_drop_variants = oneof.fields().filter(|variant| matches!(variant.proto().type_(), Type::TYPE_STRING | Type::TYPE_BYTES | Type::TYPE_MESSAGE)).collect::<Vec<_>>();
                                        if !explicit_drop_variants.is_empty() {
                                            let union_name = oneof.name();
                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "switch (this->{union_name}_variant) {{")),
                                                |w| {
                                                    for variant in explicit_drop_variants {
                                                        let variant_num = variant.number();
                                                        let variant_name = variant.name();
                                                        let rft = variant.runtime_field_type();
                                                        let variant_type = Self::protobuf_type_to_native_type(
                                                            &rft
                                                        );
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "case {variant_num}: {{")),
                                                            |w| {
                                                                w.scoped(
                                                                    |w| w.writeln(|w| write!(w, "if (!std::is_trivially_destructible<{variant_type}>::value) {{")),
                                                                    |w| w.writeln(|w| write!(w, "std::destroy_at(&(this->{union_name}_storage.{variant_name}));")),
                                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                                )?;
                                                                w.writeln(|w| write!(w, "break;"))?;
                                                                Ok(())
                                                            },
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?
                                                    }
                                                    Ok(())
                                                }, 
                                                |w| w.writeln(|w| write!(w, "}}"))
                                            )?;
                                        }
                                        w.writeln(|w| write!(w, "this->{union_name}_variant = {variant_num};"))?;
                                        w.writeln(|w| write!(w, "this->{union_name}_storage.{variant_name} = {variant_name};"))?;
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;
                            }
                        }

                        let get_wire_type = |field: &FieldDescriptor| {
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
                        };

                        w.scoped(
                            |w| w.writeln(|w| write!(w, "constexpr std::expected<void, Protobuf::Error> write_to(Protobuf::Buffer& buf) const {{")),
                            |w| {
                                for oneof in &oneofs {
                                    let union_name = oneof.name();
                                    w.scoped(
                                        |w| w.writeln(|w| write!(w, "switch (this->{union_name}_variant) {{")),
                                        |w| {
                                            for variant in oneof.fields() {
                                                let variant_name = variant.name();
                                                let variant_num = variant.number();
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case {variant_num}: {{")),
                                                    |w| {
                                                        let wire_type = get_wire_type(&variant);
                                                        let variant_id = variant.number();
                                                        w.writeln(|w| write!(w, "const auto variant_res = buf.write_tag({variant_id}, {wire_type});"))?;
                                                        w.writeln(|w| write!(w, "check_err(variant_res)"))?;
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
                                                                        w.writeln(|w| write!(w, "const auto res = buf.write_length_delimited(str.length(), str.data());"))?;
                                                                    }
                                                                    Type::TYPE_BYTES => {
                                                                        w.writeln(|w| write!(w, "const auto bytes = this->{union_name}_storage.{variant_name};"))?;
                                                                        w.writeln(|w| write!(w, "const auto res = buf.write_length_delimited(bytes.size(), bytes.data());"))?;
                                                                    }
                                                                    _ => w.writeln(|w| write!(w, "const auto res = this->{union_name}_storage.{variant_name}.write_to(buf);"))?,
                                                                }
                                                            }
                                                            RuntimeFieldType::Repeated(..) => todo!(),
                                                            RuntimeFieldType::Map(..) => todo!(),
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
                                    w.writeln(|w| write!(w, "const auto {field_name}_tag_res = buf.write_tag({field_id}, {wire_tag});"))?;
                                    w.writeln(|w| write!(w, "check_err({field_name}_tag_res)"))?;

                                    match field.runtime_field_type() {
                                        RuntimeFieldType::Singular(..) => {
                                            match field.proto().type_() {
                                                Type::TYPE_ENUM | Type::TYPE_MESSAGE => w.writeln(|w| write!(w, "const auto {field_name}_res = {field_name}.write_to(buf);"))?,
                                                Type::TYPE_STRING => w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_length_delimited({field_name}.length(), {field_name}.data());"))?,
                                                Type::TYPE_BYTES => w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_length_delimited({field_name}.size(), {field_name}.data());"))?,
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
                                                    w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_64_bit((uint64_t){field_name});"))?;
                                                }
                                                Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                    w.writeln(|w| write!(w, "const auto {field_name}_res = buf.write_32_bit((uint32_t){field_name});"))?;
                                                }
                                                _ => (),
                                            }
                                            w.writeln(|w| write!(w, "check_err({field_name}_res)"))?;
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
                                                w.writeln(|w| write!(w, "const auto {field_name}_ret = buf.write_varint(this->{field_name}.size());"))?;
                                                w.writeln(|w| write!(w, "check_err({field_name}_ret)"))?;
                                            }

                                            w.scoped(
                                                |w| w.writeln(|w| write!(w, "for (const auto& item : this->{field_name}) {{")),
                                                |w| {
                                                    if is_packed {
                                                        if let Type::TYPE_ENUM = field.proto().type_() {
                                                            w.writeln(|w| write!(w, "const auto item_ret = item.write_to(buf);"))?;
                                                        } else {
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
                                                                    w.writeln(|w| write!(w, "const auto item_ret = buf.write_64_bit((uint64_t)item);"))?;
                                                                }
                                                                Type::TYPE_FIXED32 | Type::TYPE_SFIXED32 | Type::TYPE_FLOAT => {
                                                                    w.writeln(|w| write!(w, "const auto item_ret = buf.write_32_bit((uint32_t)item);"))?;
                                                                }
                                                                Type::TYPE_ENUM => w.writeln(|w| write!(w, "const auto item_ret = item.write_to(buf);"))?,
                                                                    Type::TYPE_INT32
                                                                    | Type::TYPE_INT64
                                                                    | Type::TYPE_UINT32
                                                                    | Type::TYPE_UINT64
                                                                    | Type::TYPE_BOOL => w.writeln(|w| write!(w, "const auto item_ret = buf.write_varint(item);"))?,
                                                                    _ => unreachable!()
                                                                }
                                                        }
                                                    } else {
                                                        let wire_type = get_wire_type(&field);
                                                        let field_id = field.number();
                                                        w.writeln(|w| write!(w, "const auto wire_ret = buf.write_tag({field_id}, {wire_type});"))?;
                                                        w.writeln(|w| write!(w, "check_err(wire_ret)"))?;
                                                        match field.proto().type_() {
                                                            Type::TYPE_ENUM | Type::TYPE_MESSAGE =>  w.writeln(|w| write!(w, "const auto item_ret = item.write_to(buf);"))?,
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
                                                            Type::TYPE_BYTES => w.writeln(|w| write!(w, "const auto item_ret = buf.write_length_delimited(item.size(), item.data());"))?,
                                                            Type::TYPE_STRING => w.writeln(|w| write!(w, "const auto item_ret = buf.write_length_delimited(item.length(), item.data());"))?,
                                                            _ => unreachable!(),
                                                        }
                                                    }
                                                    w.writeln(|w| write!(w, "check_err(item_ret)"))?;
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
                                let varint_fields = get_fields_with_type(&msg, |ty| matches!(ty, Type::TYPE_INT32 | Type::TYPE_INT64 | Type::TYPE_UINT32 | Type::TYPE_UINT64 | Type::TYPE_BOOL));
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
                                                            RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(({field_type})out);"))?,
                                                            RuntimeFieldType::Repeated(..) | RuntimeFieldType::Map(..) => todo!(),
                                                        }
                                                    } else {
                                                        match field.runtime_field_type() {
                                                            RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->{field_name} = ({field_type})out;"))?,
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
                            |w| w.writeln(|w| write!(w, "constexpr std::expected<void, Protobuf::Error> write_length_delimited(const Protobuf::Buffer& buf, size_t offset, size_t field_len, varint_t field_num) {{")),
                            |w| {
                                //length delimited
                                let length_delimited_fields = get_fields_with_type(&msg, |ty| matches!(ty, Type::TYPE_MESSAGE | Type::TYPE_STRING | Type::TYPE_BYTES));

                                if length_delimited_fields.is_empty() {
                                    w.writeln(|w| write!(w, "return Err<void>(Protobuf::Error::BadVariant);"))?;
                                } else {
                                    w.writeln(|w| write!(w, "const auto bytes = (const char*)&(buf.read_bytes()[offset]);"))?;

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
                                                                                write!(w, "::parse_from(buf, offset, field_len);")?;
                                                                                Ok(())
                                                                            })?;
                                                                            w.writeln(|w| write!(w, "check_err(res)"))?;
                                                                            w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(*res);"))?;
                                                                        }
                                                                        Type::TYPE_STRING => {
                                                                            w.writeln(|w| write!(w, "std::string out;"))?;
                                                                            w.writeln(|w| write!(w, "out.assign(bytes, (size_t)field_len);"))?;
                                                                            w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(out);"))?;
                                                                        }
                                                                        Type::TYPE_BYTES => {
                                                                            todo!()
                                                                            /*
                                                                            w.writeln(|w| write!(w, "std::string out;"))?;
                                                                            w.writeln(|w| write!(w, "out.assign(field_len, bytes);"))?;
                                                                            w.writeln(|w| write!(w, "this->set_{union_name}_to_{field_name}(out);"))?;
                                                                            */
                                                                        }
                                                                        _ => unreachable!()
                                                                    }
                                                                }
                                                                _ => todo!(),
                                                            }
                                                        } else {
                                                            match field.proto().type_() {
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
                                                                                write!(w, "::parse_from(buf, offset, field_len);")?;
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
                                                                                write!(w, "::parse_from(buf, offset, field_len);")?;
                                                                                Ok(())
                                                                            })?;
                                                                        }
                                                                        RuntimeFieldType::Map(..) => todo!(),
                                                                    }

                                                                    w.writeln(|w| write!(w, "check_err(res)"))?;
                                                                    match field.runtime_field_type() {
                                                                        RuntimeFieldType::Singular(..) => w.writeln(|w| write!(w, "this->{field_name} = *res;"))?,
                                                                        RuntimeFieldType::Repeated(..) => w.writeln(|w| write!(w, "this->{field_name}.push_back(*res);"))?,
                                                                        RuntimeFieldType::Map(..) => todo!(),
                                                                    }
                                                                }
                                                                Type::TYPE_STRING => {
                                                                    match field.runtime_field_type() {
                                                                        RuntimeFieldType::Singular(..) => {
                                                                            if field.proto().proto3_optional() {
                                                                                w.writeln(|w| write!(w, "if(this->{field_name}) {{"))?;
                                                                                w.increment_tab();
                                                                                w.writeln(|w| write!(w, "auto field = *this->{field_name};"))?;
                                                                            } else {
                                                                                w.writeln(|w| write!(w, "auto field = this->{field_name};"))?;
                                                                            }
                                                                            w.writeln(|w| write!(w, "field.assign((const char*)bytes, field_len);"))?;

                                                                            if field.proto().proto3_optional() {
                                                                                w.decrement_tab();
                                                                                w.writeln(|w| write!(w, "}} else {{"))?;
                                                                                w.increment_tab();
                                                                                w.writeln(|w| write!(w, "std::string field;"))?;
                                                                                w.writeln(|w| write!(w, "field.assign((const char*) bytes, field_len);"))?;
                                                                                w.writeln(|w| write!(w, "this->{field_name} = field;"))?;
                                                                                w.decrement_tab();
                                                                                w.writeln(|w| write!(w, "}}"))?;
                                                                            }
                                                                        }
                                                                        RuntimeFieldType::Repeated(..) => {
                                                                            w.writeln(|w| write!(w, "std::string field;"))?;
                                                                            w.writeln(|w| write!(w, "field.assign((const char*)bytes, field_len);"))?;
                                                                            w.writeln(|w| write!(w, "this->{field_name}.push_back(field);"))?;
                                                                        }
                                                                        RuntimeFieldType::Map(..) => todo!(),
                                                                    }
                                                                }
                                                                Type::TYPE_BYTES => {
                                                                    todo!()
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
                            |w| {
                                w.writeln(|w| write!(w, "size_t idx = 0;"))?;
                                w.writeln(|w| write!(w, "const auto bytes = &(buf.read_bytes()[start]);"))?;
                                w.writeln(|w| write!(w, "{msg_name} out;"))?;
                                w.newline()?;

                                w.scoped(
                                    |w| w.writeln(|w| write!(w, "while (idx < len) {{")),
                                    |w| {
                                        w.writeln(|w| write!(w, "const auto fmt = get_wire_format(bytes, &idx, len);"))?;
                                        w.writeln(|w| write!(w, "check_err_with_ret({msg_name}, fmt);"))?;
                                        w.writeln(|w| write!(w, "const auto& [field_num, field_kind] = *fmt;"))?;
                                        w.scoped(
                                            |w| w.writeln(|w| write!(w, "switch (field_kind) {{")),
                                            |w| {
                                                w.scoped(
                                                    //varint
                                                    |w| w.writeln(|w| write!(w, "case 0x00: {{")),
                                                    |w| {
                                                        w.writeln(|w| write!(w, "const auto res = get_varint(bytes, &idx, len);"))?;
                                                        w.writeln(|w| write!(w, "check_err_with_ret({msg_name}, res);"))?;
                                                        w.writeln(|w| write!(w, "const auto write_res = out.write_varint(*res, field_num);"))?;
                                                        w.writeln(|w| write!(w, "check_err_with_ret({msg_name}, write_res);"))?;
                                                        w.writeln(|w| write!(w, "break;"))?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                )?;

                                                //fixed 64 bit int
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case 0x01: {{")),
                                                    |w| {
                                                        w.writeln(|w| write!(w, "auto num = 0;"))?;
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "if (idx + 7 >= len ) {{")),
                                                            |w| w.writeln(|w| write!(w, "return Err<{msg_name}>(Protobuf::Error::BadLength);")),
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?;

                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "for (auto i = 0; i < 8; i++) {{")),
                                                            |w| w.writeln(|w| write!(w, "num = (num << 8) + bytes[idx + 7 - i];")),
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?;

                                                        w.writeln(|w| write!(w, "const auto write_res = out.write_64_bit(num, field_num);"))?;
                                                        w.writeln(|w| write!(w, "check_err_with_ret({msg_name}, write_res);"))?;
                                                        w.writeln(|w| write!(w, "idx += 8;"))?;
                                                        w.writeln(|w| write!(w, "break;"))?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                )?;

                                                //length delimited
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case 0x02: {{")),
                                                    |w| {
                                                        w.writeln(|w| write!(w, "const auto res = get_varint(bytes, &idx, len);"))?;
                                                        w.writeln(|w| write!(w, "check_err_with_ret({msg_name}, res);"))?;
                                                        w.writeln(|w| write!(w, "const auto field_len = *res;"))?;
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "if(idx + field_len > len) {{")),
                                                            |w| w.writeln(|w| write!(w, "return Err<{msg_name}>(Protobuf::Error::BadLength);")),
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?;
                                                        w.writeln(|w| write!(w, "const auto write_res = out.write_length_delimited(buf, start + idx, field_len, field_num);"))?;
                                                        w.writeln(|w| write!(w, "check_err_with_ret({msg_name}, write_res);"))?;
                                                        w.writeln(|w| write!(w, "break;"))?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                )?;

                                                //fixed 32 bit int
                                                w.scoped(
                                                    |w| w.writeln(|w| write!(w, "case 0x05: {{")),
                                                    |w| {
                                                        w.writeln(|w| write!(w, "auto num = 0;"))?;
                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "if (idx + 4 >= len ) {{")),
                                                            |w| w.writeln(|w| write!(w, "return Err<{msg_name}>(Protobuf::Error::BadLength);")),
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?;

                                                        w.scoped(
                                                            |w| w.writeln(|w| write!(w, "for (auto i = 0; i < 4; i++) {{")),
                                                            |w| w.writeln(|w| write!(w, "num = (num << 8) + bytes[idx + 3 - i];")),
                                                            |w| w.writeln(|w| write!(w, "}}")),
                                                        )?;

                                                        w.writeln(|w| write!(w, "const auto write_res = out.write_32_bit(num, field_num);"))?;
                                                        w.writeln(|w| write!(w, "check_err_with_ret({msg_name}, write_res);"))?;
                                                        w.writeln(|w| write!(w, "idx += 4;"))?;
                                                        w.writeln(|w| write!(w, "break;"))?;
                                                        Ok(())
                                                    },
                                                    |w| w.writeln(|w| write!(w, "}}")),
                                                )?;

                                                w.writeln(|w| write!(w, "default: return Err<{msg_name}>(Protobuf::Error::BadVariant);"))?;
                                                Ok(())
                                            },
                                            |w| w.writeln(|w| write!(w, "}}")),
                                        )?;
                                        Ok(())
                                    },
                                    |w| w.writeln(|w| write!(w, "}}")),
                                )?;
                                w.writeln(|w| write!(w, "return Ok(out);"))?;
                                Ok(())
                            },
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
        RuntimeType::String => "std::string",
        RuntimeType::VecU8 => "Bytes",
        RuntimeType::Enum(e) => e.name(),
        RuntimeType::Message(m) => m.name(),
    }
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

