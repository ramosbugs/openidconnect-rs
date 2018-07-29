///
/// Helper trait to convert struct values to the types returned by the parent trait getters.
///
pub trait TraitStructExtract<'a, T> {
    fn extract(&'a self) -> T;
}
///
/// Specialization that clones the struct field.
///
impl<'a, U: Clone> TraitStructExtract<'a, U> for U {
    #[inline(always)]
    fn extract(&'a self) -> U {
        self.clone()
    }
}
///
/// Specialization that borrows a reference to the struct field.
///
impl<'a, U> TraitStructExtract<'a, &'a U> for U {
    #[inline(always)]
    fn extract(&'a self) -> &'a U {
        self
    }
}
///
/// Specialization that extracts `Option<U>` as `Option<&U>`.
///
impl<'a, U> TraitStructExtract<'a, Option<&'a U>> for Option<U> {
    #[inline(always)]
    fn extract(&'a self) -> Option<&'a U> {
        self.as_ref()
    }
}

// FIXME: remove
/*
pub trait DeserializeMapValue<T: DeserializeOwned> {
    fn deserialize_next_value<'de, V: MapAccess<'de>>(map: &mut V) -> Result<T, V::Error>;
}
impl<T> DeserializeMapValue<T> for T where T: DeserializeOwned {
    fn deserialize_next_value<'de, V: MapAccess<'de>>(map: &mut V) -> Result<T, V::Error> {
        map.next_value::<T>()
    }
}
*/

///
/// Copied from oauth2-rs crate (not part of that crate's stable public interface).
///
macro_rules! new_type {
    // Convenience pattern without an impl.
    (
        $(#[$attr:meta])*
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        )
    ) => {
        new_type![
            @new_type $(#[$attr])*,
            $name(
                $(#[$type_attr])*
                $type
            ),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            impl {}
        ];
    };
    // Main entry point with an impl.
    (
        $(#[$attr:meta])*
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        )
        impl {
            $($item:tt)*
        }
    ) => {
        new_type![
            @new_type $(#[$attr])*,
            $name(
                $(#[$type_attr])*
                $type
            ),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            impl {
                $($item)*
            }
        ];
    };
    // Actual implementation, after stringifying the #[doc] attr.
    (
        @new_type $(#[$attr:meta])*,
        $name:ident(
            $(#[$type_attr:meta])*
            $type:ty
        ),
        $new_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(#[$attr])*
        #[derive(Clone, Debug, Eq, Hash, Ord, PartialOrd, PartialEq)]
        pub struct $name(
            $(#[$type_attr])*
            $type
        );
        impl $name {
            $($item)*
        }
        impl NewType<$type> for $name {
            #[doc = $new_doc]
            fn new(s: $type) -> Self {
                $name(s)
            }
        }
        impl Deref for $name {
            type Target = $type;
            fn deref(&self) -> &$type {
                &self.0
            }
        }
    }
}

///
/// Copied from oauth2-rs crate (not part of that crate's stable public interface).
///
macro_rules! new_secret_type {
    (
        $(#[$attr:meta])*
        $name:ident($type:ty)
    ) => {
        new_secret_type![
            $(#[$attr])*
            $name($type)
            impl {}
        ];
    };
    (
        $(#[$attr:meta])*
        $name:ident($type:ty)
        impl {
            $($item:tt)*
        }
    ) => {
        new_secret_type![
            $(#[$attr])*,
            $name($type),
            concat!(
                "Create a new `",
                stringify!($name),
                "` to wrap the given `",
                stringify!($type),
                "`."
            ),
            concat!("Get the secret contained within this `", stringify!($name), "`."),
            impl {
                $($item)*
            }
        ];
    };
    (
        $(#[$attr:meta])*,
        $name:ident($type:ty),
        $new_doc:expr,
        $secret_doc:expr,
        impl {
            $($item:tt)*
        }
    ) => {
        $(
            #[$attr]
        )*
        #[derive(Clone, PartialEq)]
        pub struct $name($type);
        impl $name {
            $($item)*
        }
        impl SecretNewType<$type> for $name {
            #[doc = $new_doc]
            fn new(s: $type) -> Self {
                $name(s)
            }
            ///
            #[doc = $secret_doc]
            ///
            /// # Security Warning
            ///
            /// Leaking this value may compromise the security of the OAuth2 flow.
            ///
            fn secret(&self) -> &$type { &self.0 }
        }
        impl Debug for $name {
            fn fmt(&self, f: &mut Formatter) -> Result<(), FormatterError> {
                write!(f, concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

///
/// Macro to generate a trait containing the specified getters, a struct to store the specified
/// fields, and an implementation of the trait for the struct.
///
/// This macro reduces the redundancy of implementing an extensible struct with a default
/// implementation adhering to the spec.
///
macro_rules! trait_struct {
    // Convenience pattern omitting `impl[...] trait[...] for struct[...], with a trailing comma
    // after the last struct field.
    (
        trait $trait_name:ident[$($trait_types:tt)*] : [$($trait_bounds:tt)*]
        $(#[$struct_attr:meta])*
        struct $struct_name:ident[$($struct_types:tt)*] {
            $(
                $(#[$attr:meta])*
                $field_name:ident($trait_type:ty) <- $field_type:ty,
            )+
        }
    ) => {
        trait_struct! {
            trait $trait_name[$($trait_types)*] : [$($trait_bounds)*]
            $(#[$struct_attr])*
            struct $struct_name[$($struct_types)*] {
                $(
                    $(#[$attr])*
                    $field_name($trait_type) <- $field_type
                ),+
            }
            impl[] trait[] for struct []
        }
    };
    // Convenience pattern omitting `impl[...] trait[...] for struct[...], without a trailing comma
    // after the last struct field.
    (
        trait $trait_name:ident[$($trait_types:tt)*] : [$($trait_bounds:tt)*]
        $(#[$struct_attr:meta])*
        struct $struct_name:ident[$($struct_types:tt)*] {
            $(
                $(#[$attr:meta])*
                $field_name:ident($trait_type:ty) <- $field_type:ty
            ),+
        }
    ) => {
        trait_struct! {
            trait $trait_name[$($trait_types)*] : [$($trait_bounds)*]
            $(#[$struct_attr])*
            struct $struct_name[$($struct_types)*] {
                $(
                    $(#[$attr])*
                    $field_name($trait_type) <- $field_type
                ),+
            }
            impl[] trait[] for struct []
        }
    };
    // Convenience pattern with a trailing comma after the last struct field.
    (
        trait $trait_name:ident[$($trait_types:tt)*] : [$($trait_bounds:tt)*] {
            $($func:tt)*
        }
        $(#[$struct_attr:meta])*
        struct $struct_name:ident[$($struct_types:tt)*] {
            $(
                $(#[$attr:meta])*
                $field_name:ident($trait_type:ty) <- $field_type:ty,
            )+
        }
        impl[$($impl_generics:tt)*] trait[$($trait_generics:tt)*]
        for struct [$($struct_generics:tt)*]
    ) => {
        trait_struct! {
            trait $trait_name[$($trait_types)*] : [$($trait_bounds)*] {
                $($func)*
            }
            $(#[$struct_attr])*
            struct $struct_name[$($struct_types)*] {
                $(
                    $(#[$attr])*
                    $field_name($trait_type) <- $field_type
                ),+
            }
            impl[$($impl_generics)*] trait[$($trait_generics)*] for struct [$($struct_generics)*]
        }
    };
    // Actual implementation.
    (
        trait $trait_name:ident[$($trait_types:tt)*] : [$($trait_bounds:tt)*] {
            $($func:tt)*
        }
        $(#[$struct_attr:meta])*
        struct $struct_name:ident[$($struct_types:tt)*] {
            $(
                $(#[$attr:meta])*
                $field_name:ident($trait_type:ty) <- $field_type:ty
            ),+
        }
        impl[$($impl_generics:tt)*] trait[$($trait_generics:tt)*]
        for struct [$($struct_generics:tt)*]
    ) => {
        pub trait $trait_name<$($trait_types)*> : $($trait_bounds)* {
            $($func)*
            $(
                fn $field_name(&self) -> $trait_type;
            )+
        }
        $(
            #[$struct_attr]
        )*
        pub struct $struct_name<$($struct_types)*> {
            $(
                $(
                    #[$attr]
                )*
                $field_name: $field_type,
            )+
        }
        impl<$($impl_generics)*> $trait_name<$($trait_generics)*>
        for $struct_name<$($struct_generics)*> {
            $(
                fn $field_name(&self) -> $trait_type {
                    TraitStructExtract::<$trait_type>::extract(&self.$field_name)
                }
            )+
        }
    };
}

macro_rules! deserialize_fields {
    (@field_str Option(Seconds($field:ident))) => { stringify![$field] };
    (@field_str Option($field:ident)) => { stringify![$field] };
    (@field_str LanguageTag($field:ident)) => { stringify![$field] };
    (@field_str $field:ident) => { stringify![$field] };
    (@let_none Option(Seconds($field:ident))) => { let mut $field = None; };
    (@let_none Option($field:ident)) => { let mut $field = None; };
    (@let_none LanguageTag($field:ident)) => { let mut $field = None; };
    (@let_none $field:ident) => { let mut $field = None; };
    (@case $map:ident $key:ident $language_tag_opt:ident Option(Seconds($field:ident))) => {
        if $field.is_some() {
            return Err(serde::de::Error::duplicate_field(stringify!($field)));
        } else if let Some(language_tag) = $language_tag_opt {
            return Err(
                serde::de::Error::custom(
                    format!(
                        concat!("unexpected language tag `{}` for key `", stringify!($field), "`"),
                        language_tag.as_ref()
                    )
                )
            );
        }
        let seconds = $map.next_value::<Option<u64>>()?;
        $field = seconds.map(Duration::from_secs);
    };
    (@case $map:ident $key:ident $language_tag_opt:ident Option($field:ident)) => {
        if $field.is_some() {
            return Err(serde::de::Error::duplicate_field(stringify!($field)));
        } else if let Some(language_tag) = $language_tag_opt {
            return Err(
                serde::de::Error::custom(
                    format!(
                        concat!("unexpected language tag `{}` for key `", stringify!($field), "`"),
                        language_tag.as_ref()
                    )
                )
            );
        }
        $field = $map.next_value()?;
    };
    (@case $map:ident $key:ident $language_tag_opt:ident LanguageTag($field:ident)) => {
        let hash_map =
            if let Some(ref mut hash_map) = $field {
                hash_map
            } else {
                let new = HashMap::new();
                $field = Some(new);
                $field.as_mut().unwrap()
            };
        if hash_map.contains_key(&$language_tag_opt) {
            return Err(serde::de::Error::custom(format!("duplicate field `{}`", $key)));
        }

        hash_map.insert($language_tag_opt, $map.next_value()?);
    };
    (@case $map:ident $key:ident $language_tag_opt:ident $field:ident) => {
        if $field.is_some() {
            return Err(serde::de::Error::duplicate_field(stringify!($field)));
        } else if let Some(language_tag) = $language_tag_opt {
            return Err(
                serde::de::Error::custom(
                    format!(
                        concat!("unexpected language tag `{}` for key `", stringify!($field), "`"),
                        language_tag.as_ref()
                    )
                )
            );
        }
        $field = Some($map.next_value()?);
    };
    (@struct_recurs [$($struct_type:tt)+] {
        $($name:ident: $e:expr),* => [Option(Seconds($field_new:ident))] $([$($entry:tt)+])*
    }) => {
        deserialize_fields![
            @struct_recurs [$($struct_type)+] {
                $($name: $e,)* $field_new: $field_new => $([$($entry)+])*
            }
        ]
    };
    (@struct_recurs [$($struct_type:tt)+] {
        $($name:ident: $e:expr),* => [Option($field_new:ident)] $([$($entry:tt)+])*
    }) => {
        deserialize_fields![
            @struct_recurs [$($struct_type)+] {
                $($name: $e,)* $field_new: $field_new => $([$($entry)+])*
            }
        ]
    };
    (@struct_recurs [$($struct_type:tt)+] {
        $($name:ident: $e:expr),* => [LanguageTag($field_new:ident)] $([$($entry:tt)+])*
    }) => {
        deserialize_fields![
            @struct_recurs [$($struct_type)+] {
                $($name: $e,)* $field_new: $field_new => $([$($entry)+])*
            }
        ]
    };
    (@struct_recurs [$($struct_type:tt)+] {
        $($name:ident: $e:expr),* => [$field_new:ident] $([$($entry:tt)+])*
    }) => {
        deserialize_fields![
            @struct_recurs [$($struct_type)+] {
                $($name: $e,)* $field_new:
                    $field_new
                        .ok_or_else(|| serde::de::Error::missing_field(stringify!($field_new)))? =>
                            $([$($entry)+])*
            }
        ]
    };
    // Actually instantiate the struct.
    (@struct_recurs [$($struct_type:tt)+] {
        $($name:ident: $e:expr),+ =>
    }) => {
        $($struct_type)+ {
            $($name: $e),+
        }
    };
    // Main entry point
    (
        $map:ident {
            $([$($entry:tt)+])+
        }
    ) => {
        // let mut field_name = None;
        $(deserialize_fields![@let_none $($entry)+];)+
        while let Some(key) = $map.next_key::<String>()? {
            let (field_name, language_tag_opt) = split_language_tag_key(&key);
                match field_name {
                    $(
                        // "field_name" => { ... }
                        deserialize_fields![@field_str $($entry)+] => {
                            deserialize_fields![@case $map key language_tag_opt $($entry)+];
                        },
                    )+
                    // Ignore unknown fields.
                    _ => {
                        $map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
        }
        Ok(deserialize_fields![@struct_recurs [Self::Value] { => $([$($entry)+])* }])
    };
}

macro_rules! serialize_fields {
    (@case $self:ident $map:ident Option(Seconds($field:ident))) => {
        if let Some(ref $field) = $self.$field {
            $map.serialize_entry(stringify!($field), &$field.as_secs())?;
        }
    };
    (@case $self:ident $map:ident Option($field:ident)) => {
        if let Some(ref $field) = $self.$field {
            $map.serialize_entry(stringify!($field), $field)?;
        }
    };
    (@case $self:ident $map:ident LanguageTag($field:ident)) => {
        if let Some(ref field_map) = $self.$field {
            for (language_tag_opt, $field) in field_map {
                if let Some(ref language_tag) = *language_tag_opt {
                    $map.serialize_entry(
                        &format!(concat!(stringify!($field), "#{}"), language_tag.as_ref()),
                        &$field
                    )?;
                } else {
                    $map.serialize_entry(stringify!($field), &$field)?;
                }
            }
        }
    };
    (@case $self:ident $map:ident $field:ident) => {
        $map.serialize_entry(stringify!($field), &$self.$field)?;
    };
    // Main entry point
    (
        $self:ident -> $serializer:ident {
            $([$($entry:tt)+])+
        }
    ) => {
        let mut map = $serializer.serialize_map(None)?;
        $(
            serialize_fields![@case $self map $($entry)+];
        )+
        map.end()
    };
}

macro_rules! field_getter_decls {
    (@case $self:ident $field:ident Option < bool >) => {
        fn $field(&$self) -> Option<bool>;
    };
    (@case $self:ident $field:ident Option < $type:ty >) => {
        fn $field(&$self) -> Option<&$type>;
    };
    (@case $self:ident $field:ident $type:ty) => {
        fn $field(&$self) -> &$type;
    };
    // Main entry point
    (
        $self:ident {
            $(
                $field:ident[$($entry:tt)+],
            )+
        }
    ) => {
        $(
            field_getter_decls![@case $self $field $($entry)+];
        )+
    };
}

macro_rules! field_getters {
    (@case $self:ident [$zero:expr] $field:ident Option < bool >) => {
        fn $field(&$self) -> Option<bool> {
            $zero.$field
        }
    };
    (@case $self:ident [$zero:expr] $field:ident Option < $type:ty >) => {
        fn $field(&$self) -> Option<&$type> {
            $zero.$field.as_ref()
        }
    };
    (@case $self:ident [$zero:expr] $field:ident $type:ty) => {
        fn $field(&$self) -> &$type {
            &$zero.$field
        }
    };
    (@case pub $self:ident [$zero:expr] $field:ident Option < bool >) => {
        pub fn $field(&$self) -> Option<bool> {
            $zero.$field
        }
    };
    (@case pub $self:ident [$zero:expr] $field:ident Option < $type:ty >) => {
       pub  fn $field(&$self) -> Option<&$type> {
            $zero.$field.as_ref()
        }
    };
    (@case pub $self:ident [$zero:expr] $field:ident $type:ty) => {
        pub fn $field(&$self) -> &$type {
            &$zero.$field
        }
    };
    (@case $self:ident [$zero:expr] $field:ident() Option < bool >) => {
        fn $field(&$self) -> Option<bool> {
            $zero.$field()
        }
    };
    (@case $self:ident [$zero:expr] $field:ident() Option < $type:ty >) => {
        fn $field(&$self) -> Option<&$type> {
            $zero.$field()
        }
    };
    (@case $self:ident [$zero:expr] $field:ident() $type:ty) => {
        fn $field(&$self) -> &$type {
            $zero.$field()
        }
    };
    // Main entry points
    (
        $self:ident [$zero:expr] {
            $(
                $field:ident[$($entry:tt)+],
            )+
        }
    ) => {
        $(
            field_getters![@case $self [$zero] $field $($entry)+];
        )+
    };
    (
        pub $self:ident [$zero:expr] {
            $(
                $field:ident[$($entry:tt)+],
            )+
        }
    ) => {
        $(
            field_getters![@case pub $self [$zero] $field $($entry)+];
        )+
    };
    (
        $self:ident [$zero:expr]() {
            $(
                $field:ident[$($entry:tt)+],
            )+
        }
    ) => {
        $(
            field_getters![@case $self [$zero] $field() $($entry)+];
        )+
    };
}

macro_rules! field_setter_decls {
    (@case $setter:ident $field:ident Option < HashMap < Option < LanguageTag > , $type:ty > >) => {
        fn $setter(
            self,
            $field: Option<$type>,
            language_tag: Option<LanguageTag>
        ) -> Self;
    };
    (@case $setter:ident $field:ident $type:ty) => {
        fn $setter(
            self,
            $field: $type
        ) -> Self;
    };
    // Main entry point
    (
        $(
            $setter:ident -> $field:ident[$($entry:tt)+],
        )+
    ) => {
        $(
            field_setter_decls![@case $setter $field $($entry)+];
        )+
    };
}

macro_rules! field_setters {
    (@case $self:ident [$zero:expr] $setter:ident $field:ident Option < HashMap < Option < LanguageTag > , $type:ty > >) => {
        fn $setter(
            mut $self,
            $field: Option<$type>,
            language_tag: Option<LanguageTag>
        ) -> Self {
            if let Some(temp) = $field {
                if $zero.$field.is_none() {
                    $zero.$field = Some(HashMap::new());
                }
                if let Some(ref mut hash_map) = $zero.$field {
                    hash_map.insert(language_tag, temp);
                }
            } else {
                let set_to_none =
                    if let Some(ref mut hash_map) = $zero.$field {
                        hash_map.remove(&language_tag);
                        hash_map.is_empty()
                    } else {
                        false
                    };
                if set_to_none {
                    $zero.$field = None;
                }
            }
            $self
        }
    };
    (@case $self:ident [$zero:expr] $setter:ident $field:ident $type:ty) => {
        fn $setter(
            mut $self,
            $field: $type
        ) -> Self {
            $zero.$field = $field;
            $self
        }
    };
    // Main entry point
    (
        $self:ident [$zero:expr] {
            $(
                $setter:ident -> $field:ident[$($entry:tt)+],
            )+
        }
    ) => {
        $(
            field_setters![@case $self [$zero] $setter $field $($entry)+];
        )+
    };
}
