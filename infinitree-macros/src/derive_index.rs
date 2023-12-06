#[rustfmt::skip]

use proc_macro2::{Span, TokenStream};
use proc_macro_crate::{crate_name, FoundCrate};
use quote::quote;
use syn::{Data, DataStruct, DeriveInput, Field, Fields, Ident, Lit, LitStr, Type};

struct StructField {
    field: Field,
    skip: bool,
    rename: String,
    strategy: TokenStream,
}

pub fn crate_name_token() -> TokenStream {
    let rustdoc =
        std::env::var("RUSTDOC_TEST_LINE").or_else(|_| std::env::var("UNSTABLE_RUSTDOC_TEST_LINE"));
    if rustdoc.is_ok() {
        // running in rustdoc
        return quote!(infinitree);
    }

    match crate_name("infinitree").expect("couldn't find infinitree") {
        FoundCrate::Itself => quote!(crate),
        FoundCrate::Name(name) => {
            let ident = Ident::new(&name, Span::call_site());
            quote!( ::#ident )
        }
    }
}

pub fn expand(infinitree_crate: TokenStream, input: DeriveInput) -> syn::Result<TokenStream> {
    let fields = match input.data {
        Data::Struct(DataStruct {
            fields: Fields::Named(fields),
            ..
        }) => fields.named,
        _ => panic!("this derive macro only works on structs with named fields"),
    };

    let fields = fields
        .into_iter()
        .filter_map(|f| {
            let field = f
                .attrs
                .iter()
                .filter(|attr| attr.path().is_ident("infinitree"))
                .fold(
                    StructField {
                        field: f.clone(),
                        skip: false,
                        rename: f.ident.expect("named field expected").to_string(),
                        strategy: quote! ( #infinitree_crate::fields::LocalField ),
                    },
                    |mut field, attr| {
                        attr.parse_nested_meta(|meta| {
                            if meta.path.is_ident("name") {
                                field.rename = meta.value()?.parse::<LitStr>()?.value();
                                return Ok(());
                            }

                            if meta.path.is_ident("skip") {
                                field.skip = true;
                                return Ok(());
                            }

                            if meta.path.is_ident("strategy") {
                                let strategy: Type =
                                    syn::parse_str(&meta.value()?.parse::<LitStr>()?.value())?;
                                field.strategy = quote!( #strategy );
                                return Ok(());
                            }

                            Err(meta.error("unrecognized repr"))
                        })
                        .expect("bad attributes");

                        field
                    },
                );

            match field.skip {
                false => Some(field),
                true => None,
            }
        })
        .collect::<Vec<_>>();

    let getters = fields
        .iter()
        .map(|f| {
            let method_name = Ident::new(&f.rename, Span::mixed_site());
            let field_name_str = Lit::Str(LitStr::new(f.rename.as_str(), Span::mixed_site()));
            let field_name = &f.field.ident;
            let field_ty = &f.field.ty;
            let strategy = &f.strategy;

            Ok(quote! {
		#[inline]
                pub fn #method_name(&'_ self) -> #infinitree_crate::fields::Intent<Box<#strategy<#field_ty>>> {
		    use #infinitree_crate::fields::{Intent, strategy::Strategy};
		    Intent::new(
			#field_name_str,
			Box::new(#strategy::for_field(
			    &self.#field_name,
			)),
		    )
                }
            })
        })
        .collect::<syn::Result<TokenStream>>()?;

    let strategies = fields
        .iter()
        .map(|f| {
            let field_name = Ident::new(&f.rename, Span::mixed_site());
            quote! { self.#field_name().into(), }
        })
        .collect::<TokenStream>();

    let field_name_list = fields
        .iter()
        .map(|f| {
            let field_name_str = Lit::Str(LitStr::new(f.rename.as_str(), Span::mixed_site()));
            quote! { #field_name_str.into(), }
        })
        .collect::<TokenStream>();

    let st_name = input.ident;
    let (impl_generics, ty_generics, where_clause) = input.generics.split_for_impl();

    {
        Ok(quote! {
        #[automatically_derived]
        impl #impl_generics #st_name #ty_generics #where_clause {
            #getters

            pub fn fields(&self) -> Vec<String> {
                vec![#field_name_list]
            }
        }


        impl #impl_generics #infinitree_crate::Index for #st_name #ty_generics #where_clause {
            fn store_all(&'_ self) -> #infinitree_crate::anyhow::Result<Vec<#infinitree_crate::fields::Intent<Box<dyn #infinitree_crate::fields::Store>>>> {
                Ok(vec![#strategies])
            }

            fn load_all(&'_ self) -> #infinitree_crate::anyhow::Result<Vec<#infinitree_crate::fields::Intent<Box<dyn #infinitree_crate::fields::Load>>>> {
                Ok(vec![#strategies])
            }
        }
        })
    }
}
