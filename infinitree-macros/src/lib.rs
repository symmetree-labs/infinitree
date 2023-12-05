#![forbid(unsafe_code)]
#![deny(clippy::all)]

use proc_macro::TokenStream;
use syn::{parse_macro_input, DeriveInput};

mod derive_index;

/// Example use of the derive macro:
///
/// ```
/// use infinitree::fields::{Serialized, VersionedMap};
/// use serde::{Serialize, Deserialize};
///
/// #[derive(Serialize, Deserialize)]
/// struct PlantHealth {
///     id: usize,
///     air_humidity: usize,
///     soil_humidity: usize,
///     temperature: f32
/// }
///
/// #[derive(infinitree::Index, Default, Clone)]
/// pub struct Measurements {
///     // rename the field when serializing
///     #[infinitree(name = "last_time")]
///     _old_last_time: Serialized<String>,
///
///     #[infinitree(name = "last_time2")]
///     last_time: Serialized<usize>,
///
///     // only store the keys in the index, not the values
///     #[infinitree(strategy = "infinitree::fields::SparseField")]
///     measurements: VersionedMap<usize, PlantHealth>,
///
///     // skip the next field when loading & serializing
///     #[infinitree(skip)]
///     current_time: usize,
/// }
/// ```
#[proc_macro_derive(Index, attributes(infinitree))]
pub fn derive_index_macro(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    derive_index::expand(derive_index::crate_name_token(), input)
        .unwrap_or_else(syn::Error::into_compile_error)
        .into()
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_macro() {
        use quote::quote;
        use syn::parse_quote;

        let input = parse_quote! {
        #[derive(Default, Index)]
        pub struct TestStruct<T> {
            /// A field with both an accessor method and serialized to storage
            unattributed: ChunkIndex,

            /// Rename the field to `renamed_chunks` both in serialized form
            /// and accessor method
            #[infinitree(name = "renamed_chunks")]
            chunks: ChunkIndex,

            /// Skip generating accessors and exclude from on-disk structure
            #[infinitree(skip)]
            _unreferenced: ChunkIndex,

            /// Skip generating accessors and exclude from on-disk structure
            #[infinitree(strategy = "infinitree::fields::SparseField")]
            strategizing: ChunkIndex,

            #[infinitree(skip)]
            _ph: PhantomData<T>
        }
        };

        let result = super::derive_index::expand(quote::quote!(::infinitree), input).unwrap();

        #[rustfmt::skip]
        let expected = quote! {
        #[automatically_derived]
        impl<T> TestStruct<T> {
            #[inline]
            pub fn unattributed(&'_ self) -> ::infinitree::fields::Intent<Box<::infinitree::fields::LocalField<ChunkIndex>>> {
                use ::infinitree::fields::{Intent, strategy::Strategy};
                Intent::new(
                    "unattributed",
                    Box::new(::infinitree::fields::LocalField::for_field(
			&self.unattributed,
		    )),
                )
            }
            #[inline]
            pub fn renamed_chunks(&'_ self) -> ::infinitree::fields::Intent<Box<::infinitree::fields::LocalField<ChunkIndex>>> {
                use ::infinitree::fields::{Intent, strategy::Strategy};
                Intent::new(
                    "renamed_chunks",
                    Box::new(::infinitree::fields::LocalField::for_field(
			&self.chunks,
		    )),
                )
            }
            #[inline]
            pub fn strategizing(&'_ self) -> ::infinitree::fields::Intent<Box<infinitree::fields::SparseField<ChunkIndex>>> {
                use ::infinitree::fields::{Intent, strategy::Strategy};
                Intent::new(
                    "strategizing",
                    Box::new(infinitree::fields::SparseField::for_field(
                        &self.strategizing,
                    )),
                )
            }
            pub fn fields(&self) -> Vec<String> {
                vec!["unattributed".into(),
		     "renamed_chunks".into(),
		     "strategizing".into(),
		]
            }
        }
        impl<T> ::infinitree::Index for TestStruct<T> {
            fn store_all(&'_ self) -> ::infinitree::anyhow::Result<Vec<::infinitree::fields::Intent<Box<dyn ::infinitree::fields::Store>>>> {
                Ok(vec![
                    self.unattributed().into(),
                    self.renamed_chunks().into(),
                    self.strategizing().into(),
                ])
            }
            fn load_all(&'_ self) -> ::infinitree::anyhow::Result<Vec<::infinitree::fields::Intent<Box<dyn ::infinitree::fields::Load>>>> {
                Ok(vec![
                    self.unattributed().into(),
                    self.renamed_chunks().into(),
                    self.strategizing().into(),
                ])
            }
        }
            };

        assert_eq!(result.to_string(), expected.to_string());
    }
}
