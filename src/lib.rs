use protobuf::reflect::{FileDescriptor, EnumDescriptor, MessageDescriptor, ServiceDescriptor};
mod topo_sort;
pub mod writers;

pub struct ProtobufParser<T: ProtobufBindingsWriter, WriteState> {
    parser: protobuf_parse::Parser,
    writer: T,
    state: WriteState,
}

pub use topo_sort::{MessageKind, CollectionDependencies, ProtobufType};
use protobuf::reflect::RuntimeFieldType;

pub trait ProtobufBindingsWriter {
    type WriterOptions;
    fn with_writer_options(&mut self, options: Self::WriterOptions);
    fn writer(&mut self) -> &mut impl std::io::Write;
    fn write_prelude(&mut self) -> std::io::Result<()>;
    fn write_file_header(&mut self, fd: &FileDescriptor) -> std::io::Result<()>;
    fn write_file_closer(&mut self, fd: &FileDescriptor) -> std::io::Result<()>;
    fn write_enum(&mut self, fd: &FileDescriptor, enm: &EnumDescriptor) -> std::io::Result<()>;
    fn write_message(&mut self, fd: &FileDescriptor, enm: &MessageDescriptor, collection_deps: &CollectionDependencies) -> std::io::Result<()>;
    fn write_service(&mut self, fd: &FileDescriptor, ext: &ServiceDescriptor) -> std::io::Result<()>;
    fn protobuf_type_to_native_type(
        protobuf_type: &RuntimeFieldType,
    ) -> &str;
}

use crate::topo_sort::DependentMessageKind;

pub struct Initalized;
pub struct Parsed {
    sorted: Vec<(FileDescriptor, Vec<DependentMessageKind>)>,
}
pub struct Written;

impl <T: ProtobufBindingsWriter> ProtobufParser<T, Initalized> {
    pub fn with_writer(writer: T) -> anyhow::Result<Self> {
        let mut parser = protobuf_parse::Parser::new();
        parser.protoc();
        parser.protoc_path(&protoc_bin_vendored::protoc_bin_path()?);
        Ok(Self{parser, writer, state: Initalized})
    }

    pub fn with_writer_options(&mut self, options: T::WriterOptions) {
        self.writer.with_writer_options(options)
    }

    pub fn with_inputs<P: AsRef<std::path::Path>>(&mut self, inputs: &[P]) {
        self.parser.inputs(inputs);
    }

    pub fn with_includes<P: AsRef<std::path::Path>>(&mut self, includes: &[P]) {
        self.parser.includes(includes);
    }

    pub fn parse(self) -> anyhow::Result<ProtobufParser<T, Parsed>> {
        let Self {
            parser,
            writer,
            ..
        } = self;

        let parsed = parser.parse_and_typecheck()?;
        let fds = FileDescriptor::new_dynamic_fds(parsed.file_descriptors, &[])?;

        let sorted = fds.into_iter().map(|fd| {
            match crate::topo_sort::order_protoc_types(&fd) {
                Ok(ord) => Ok((fd, ord)),
                Err(e) => Err(e),
            }
        }).collect::<anyhow::Result<Vec<_>>>()?;

        Ok(ProtobufParser {
            parser,
            writer,
            state: Parsed { sorted },
        })
    }
}

impl <T: ProtobufBindingsWriter> ProtobufParser<T, Parsed> {
    pub fn write_bindings(self) -> std::io::Result<ProtobufParser<T, Written>> {
        let Self {
            parser,
            mut writer,
            state: Parsed {
                sorted,
            },
            ..
        } = self;
        writer.write_prelude()?;

        for (fd, msg_kinds) in sorted {
            writer.write_file_header(&fd)?;
            for kind in msg_kinds {
                match kind {
                    DependentMessageKind::Enum(e) => writer.write_enum(&fd, &e)?,
                    DependentMessageKind::Message(m, hc) => writer.write_message(&fd, &m, &*hc.borrow())?,
                }
            }
            for service in fd.services() {
                writer.write_service(&fd, &service)?;
            }
            writer.write_file_closer(&fd)?;
        }
        Ok(ProtobufParser{parser, writer, state: Written})
    }
}

pub struct Wrote;

impl <T: ProtobufBindingsWriter + AsRef<[u8]>> ProtobufParser<T, Written> {
    pub fn write_output_to_file<P: AsRef<std::path::Path>>(self, file_path: P) -> anyhow::Result<ProtobufParser<T, Wrote>> {
        let Self {
            parser,
            writer,
            ..
        } = self;
        std::fs::write(file_path, &writer)?;

        Ok(ProtobufParser{parser, writer, state: Wrote})
    }
}

impl <T: ProtobufBindingsWriter, S> std::io::Write for ProtobufParser<T, S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let writer = self.writer.writer();
        writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let writer = self.writer.writer();
        writer.flush()
    }
}

impl <T: ProtobufBindingsWriter, S> ProtobufParser<T, S> {
    pub fn parts(self) -> (T, protobuf_parse::Parser, S) {
        let Self {
            writer,
            parser,
            state
        } = self;
        (writer, parser, state)
    }
}
