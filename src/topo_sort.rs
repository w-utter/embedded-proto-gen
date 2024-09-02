struct TopInfo {
    dep_count: AtomicUsize,
    kind: DependentMessageKind,
    used_by: RefCell<HashSet<String>>,
    forward_declarable: RefCell<HashSet<String>>,
    collection_count: AtomicUsize,
}
use protobuf::reflect::RuntimeFieldType;

impl TopInfo {
    fn new(kind: DependentMessageKind) -> Self {
        Self {
            kind,
            dep_count: 0.into(),
            used_by: Default::default(),
            forward_declarable: Default::default(),
            collection_count: 0.into(),
        }
    }

    fn new_message(msg: MessageDescriptor) -> Self {
        Self::new(DependentMessageKind::Message(msg, Default::default()))
    }

    fn new_enum(enm: EnumDescriptor) -> Self {
        Self::new(DependentMessageKind::Enum(enm))
    }
}

fn populate_top_map(
    map: &mut HashMap<String, TopInfo>,
) -> anyhow::Result<()> {
    for TopInfo { dep_count, kind, forward_declarable, collection_count, ..} in map.values() {
        use protobuf::descriptor::field_descriptor_proto::Type;
        if let DependentMessageKind::Message(desc, cc) = kind {
            for field in desc.fields() {
                let field_name = get_type_name_from_path(field.proto().type_name());
                if matches!(field.proto().type_(), Type::TYPE_ENUM | Type::TYPE_MESSAGE) {
                    dep_count.fetch_add(1, Ordering::SeqCst);
                    let TopInfo { used_by, .. } = map.get(field_name).unwrap();
                    used_by.borrow_mut().insert(desc.full_name().to_owned());

                    match field.runtime_field_type() {
                        RuntimeFieldType::Repeated(..) => {
                            if let Type::TYPE_MESSAGE = field.proto().type_() {
                                forward_declarable.borrow_mut().insert(field_name.to_owned());
                            }
                            collection_count.fetch_add(1, Ordering::SeqCst);
                        }
                        RuntimeFieldType::Map(..) => todo!(),
                        _ => (),
                    }
                }

                match field.runtime_field_type() {
                    RuntimeFieldType::Repeated(_) => {
                        let a = &mut *cc.borrow_mut();
                        a.add_dependency(field.number(), ProtobufType::from_runtime_type(field.runtime_field_type()))
                    }
                    RuntimeFieldType::Map(..) => todo!(),
                    _ => (),
                }
            }
        }
    }
    Ok(())
}

fn get_type_name_from_path(path: &str) -> &str {
    path.split(".").last().unwrap()
}

#[derive(Debug, Clone)]
pub(crate) enum DependentMessageKind {
    Enum(EnumDescriptor),
    Message(MessageDescriptor, RefCell<CollectionDependencies>),
}

#[derive(Clone, Debug)]
pub enum MessageKind {
    Enum(EnumDescriptor),
    Message(MessageDescriptor),
}

use protobuf::reflect::RuntimeType;
#[derive(Default, Clone, Debug)]
pub struct CollectionDependencies {
    map: HashMap<i32, Vec<ProtobufType>>,
}

pub struct ProtobufType {
    ty: RuntimeFieldType,
    deps: Vec<ProtobufType>,
}

impl Clone for ProtobufType {
    fn clone(&self) -> Self {
        let deps = self.deps.clone();

        let ty = match &self.ty {
            RuntimeFieldType::Singular(s) => RuntimeFieldType::Singular(s.clone()),
            RuntimeFieldType::Repeated(r) => RuntimeFieldType::Repeated(r.clone()),
            _ => todo!(),
        };

        Self {
            deps,
            ty,
        }
    }
}

impl core::fmt::Debug for ProtobufType {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.deps.fmt(f)?;
        Ok(())
    }
}

impl ProtobufType {
    pub fn runtime_type(&self) -> &RuntimeType {
        match &self.ty {
            RuntimeFieldType::Singular(ty) | RuntimeFieldType::Repeated(ty) => ty,
            _ => todo!()
        }
    }

    pub fn field_type(&self) -> &RuntimeFieldType {
        &self.ty
    }

    fn from_runtime_type(runtime_type: RuntimeFieldType) -> Self {
        Self {
            ty: runtime_type,
            deps: Default::default(),
        }
    }

    fn new(runtime_type: RuntimeFieldType, dep: Vec<ProtobufType>) -> Self {
        Self {
            ty: runtime_type,
            deps: dep,
        }
    }

    pub fn deps(&self) -> impl Iterator<Item = &ProtobufType> {
        self.deps.iter()
    }

    pub fn has_deps(&self) -> bool {
        !self.deps.is_empty()
    }
}


impl CollectionDependencies {
    pub fn from_field_num(&self, field_num: &i32) -> &[ProtobufType] {
        self.map.get(field_num).map(AsRef::as_ref).unwrap_or_default()
    }

    pub fn from_field_num_mut(&mut self, field_num: &i32) -> Option<&mut Vec<ProtobufType>> {
        self.map.get_mut(field_num)
    }

    pub fn collection_deps(&self) -> impl Iterator<Item = &ProtobufType> {
        self.map.values().flatten()
    }

    pub fn dep_count(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    pub fn deps_by_field_num(&self) ->  impl Iterator<Item = (&i32, &[ProtobufType])> {
        self.map.iter().map(|(a, b)| (a, b.as_ref()))
    }

    fn add_dependency(&mut self, field_num: i32, val: ProtobufType) {
        if let Some(c) = self.map.get_mut(&field_num) {
            c.push(val)
        } else {
            self.map.insert(field_num, vec![val]);
        }
    }
}

fn add_message_entry(
    map: &mut HashMap<String, TopInfo>,
    entry: &MessageDescriptor,
) {
    let name = entry.full_name();
    map.insert(
        name.to_owned(),
        TopInfo::new_message(entry.clone())
    );

    for msg in entry.nested_messages() {
        add_message_entry(map, &msg);
    }

    for enm in entry.nested_enums() {
        add_enum_entry(map, &enm);
    }
}


fn add_enum_entry(
    map: &mut HashMap<String, TopInfo>,
    entry: &EnumDescriptor,
) {
    let name = entry.full_name();
    map.insert(
        name.to_owned(),
        TopInfo::new_enum(entry.clone())
    );
}

use protobuf::reflect::{FileDescriptor, MessageDescriptor, EnumDescriptor};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
 
pub(crate) fn order_protoc_types(file: &FileDescriptor) -> anyhow::Result<Vec<DependentMessageKind>> {
    let mut top_degrees = HashMap::new();
    for msg in file.messages() {
        add_message_entry(&mut top_degrees, &msg);
    }

    for enm in file.enums() {
        add_enum_entry(&mut top_degrees, &enm);
    }

    populate_top_map(&mut top_degrees)?;

    let mut empty_nodes = Vec::new();

    for TopInfo { dep_count, kind, used_by, forward_declarable, .. } in top_degrees.values() {
        if dep_count.load(Ordering::SeqCst) == 0 {
            empty_nodes.push((kind, used_by, forward_declarable));
        }
    }

    let mut ord = Vec::new();
    let mut forward_declarable_messages = HashMap::new();

    while let Some((empty_kind, field_deps, empty_node_forward_declarable)) = empty_nodes.pop() {
        for dep in &*field_deps.borrow() {
            let TopInfo { dep_count, kind, used_by, forward_declarable, ..} = top_degrees.get(dep).unwrap();

            if let DependentMessageKind::Message(empty_msg, cc) = empty_kind {
                match kind {
                    DependentMessageKind::Message(msg, tcc) => {
                        for (_, deps) in cc.borrow().deps_by_field_num() {
                            //this localizes the msg field number so that we're not getting the
                            //field num relative to the embedded msgs.
                            //FIXME: theres prob a better way to do this.
                            for f in msg.fields() {
                                match f.runtime_field_type() {
                                    RuntimeFieldType::Singular(ty) | RuntimeFieldType::Repeated(ty) => {
                                        match &ty {
                                            RuntimeType::Message(m) if m == empty_msg => {
                                                let field_num = f.number();
                                                let mut bm = tcc.borrow_mut();

                                                if let Some(a) = bm.map.get_mut(&field_num) {
                                                    if let Some(a) = a.iter_mut().find(|t| *t.runtime_type() == ty) {
                                                        a.deps = deps.to_owned();
                                                    } else {
                                                        let collection_deps = &mut *tcc.borrow_mut();
                                                        let a = cc.borrow().collection_deps().cloned().collect::<Vec<_>>();
                                                        collection_deps.add_dependency(field_num, ProtobufType::new(f.runtime_field_type(), a));
                                                    }
                                                } else {
                                                    let a = cc.borrow().collection_deps().cloned().collect::<Vec<_>>();
                                                    bm.add_dependency(field_num, ProtobufType::new(f.runtime_field_type(), a));
                                                }
                                            }
                                            _ => (),
                                        }
                                    }
                                    RuntimeFieldType::Map(..) => todo!()
                                }
                            }
                        }
                    }
                    _ => unreachable!()
                }
            }

            dep_count.fetch_sub(1, Ordering::SeqCst);
            if dep_count.load(Ordering::SeqCst) == 0 {
                empty_nodes.push((kind, used_by, forward_declarable));

                for fd in &*empty_node_forward_declarable.borrow() {
                    let TopInfo { kind, .. } = top_degrees.get(fd).unwrap();
                    forward_declarable_messages.insert(fd.to_owned(), kind.to_owned());
                }
            }
        }
        ord.push(empty_kind);
    }

    if ord.len() != top_degrees.len() {
        panic!("detected cyclic type");
    }
    let _fdm = forward_declarable_messages.into_iter().collect::<Vec<_>>();

    let cloned = ord.into_iter().cloned().collect::<Vec<_>>();
    Ok(cloned)
}
