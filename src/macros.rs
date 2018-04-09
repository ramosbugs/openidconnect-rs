///
/// Helper trait to convert struct values to the types returned by the parent trait getters.
///
pub trait TraitStructExtract<'a, T> {
    #[inline(always)]
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
        &self
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

/*
trait_struct![
    trait Foo[T: TokenType] : [Debug + DeserializeOwned + PartialEq + Serialize]
    struct Bar[T: TokenType = BasicTokenType] {
        #[serde(rename = "authorization_endpoint")]
        authorization_endpoint(u32) <- _authorization_endpoint(u32),
        #[serde(bound(deserialize = "T: DeserializeOwned"))]
        #[serde(rename = "token_type")]
        b(Option<&T>) <- _b(Option<T>),
    }
    impl[T: TokenType] trait[T] for struct[T]
];

trait_struct![
    trait Foo2[] : [Debug + DeserializeOwned + PartialEq + Serialize]
    struct Bar2[] {
        #[serde(rename = "authorization_endpoint")]
        authorization_endpoint(u32) <- _authorization_endpoint(u32),
    }
];
*/

///
/// Macro to generate a trait containing the specified getters, a struct to store the specified
/// fields, and an implementation of the trait for the struct.
///
/// This macro reduces the redundancy of implementing an extensible struct with a default
/// implementation adhering to the spec.
///
/// # Example
///
/// FIXME: add example
///
#[macro_export] macro_rules! trait_struct {
    // Convenience pattern omitting `impl[...] trait[...] for struct[...], with a trailing comma
    // after the last struct field.
    (
        trait $trait_name:ident[$($trait_types:tt)*] : [$($trait_bounds:tt)*]
        struct $struct_name:ident[$($struct_types:tt)*] {
            $(
                $(#[$attr:meta])*
                $trait_fn:ident($trait_type:ty) <- $field_name:ident($field_type:ty),
            )+
        }
    ) => {
        trait_struct! {
            trait $trait_name[$($trait_types)*] : [$($trait_bounds)*]
            struct $struct_name[$($struct_types)*] {
                $(
                    $(#[$attr])*
                    $trait_fn($trait_type) <- $field_name($field_type)
                ),+
            }
            impl[] trait[] for struct []
        }
    };
    // Convenience pattern omitting `impl[...] trait[...] for struct[...], without a trailing comma
    // after the last struct field.
    (
        trait $trait_name:ident[$($trait_types:tt)*] : [$($trait_bounds:tt)*]
        struct $struct_name:ident[$($struct_types:tt)*] {
            $(
                $(#[$attr:meta])*
                $trait_fn:ident($trait_type:ty) <- $field_name:ident($field_type:ty)
            ),+
        }
    ) => {
        trait_struct! {
            trait $trait_name[$($trait_types)*] : [$($trait_bounds)*]
            struct $struct_name[$($struct_types)*] {
                $(
                    $(#[$attr])*
                    $trait_fn($trait_type) <- $field_name($field_type)
                ),+
            }
            impl[] trait[] for struct []
        }
    };
    // Convenience pattern with a trailing comma after the last struct field.
    (
        trait $trait_name:ident[$($trait_types:tt)*] : [$($trait_bounds:tt)*]
        struct $struct_name:ident[$($struct_types:tt)*] {
            $(
                $(#[$attr:meta])*
                $trait_fn:ident($trait_type:ty) <- $field_name:ident($field_type:ty),
            )+
        }
        impl[$($impl_generics:tt)*] trait[$($trait_generics:tt)*]
        for struct [$($struct_generics:tt)*]
    ) => {
        trait_struct! {
            trait $trait_name[$($trait_types)*] : [$($trait_bounds)*]
            struct $struct_name[$($struct_types)*] {
                $(
                    $(#[$attr])*
                    $trait_fn($trait_type) <- $field_name($field_type)
                ),+
            }
            impl[$($impl_generics)*] trait[$($trait_generics)*] for struct [$($struct_generics)*]
        }
    };
    // Actual implementation.
    (
        trait $trait_name:ident[$($trait_types:tt)*] : [$($trait_bounds:tt)*]
        struct $struct_name:ident[$($struct_types:tt)*] {
            $(
                $(#[$attr:meta])*
                $trait_fn:ident($trait_type:ty) <- $field_name:ident($field_type:ty)
            ),+
        }
        impl[$($impl_generics:tt)*] trait[$($trait_generics:tt)*]
        for struct [$($struct_generics:tt)*]
    ) => {
        pub trait $trait_name<$($trait_types)*> : $($trait_bounds)* {
            $(
                fn $trait_fn(&self) -> $trait_type;
            )+
        }
        #[derive(Debug, Deserialize, PartialEq, Serialize)]
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
                fn $trait_fn(&self) -> $trait_type {
                    TraitStructExtract::<$trait_type>::extract(&self.$field_name)
                }
            )+
        }
    };
}
