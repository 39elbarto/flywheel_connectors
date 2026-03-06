//! Proc-macro wrappers for `fcp-async-core` runtime attributes.

#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::{Expr, ItemFn, Lit, Meta, parse_macro_input};

#[derive(Clone, Copy)]
enum Flavor {
    CurrentThread,
    MultiThread,
}

fn parse_flavor(args: TokenStream, default: Flavor) -> syn::Result<Flavor> {
    let metas =
        syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated.parse(args)?;
    let mut flavor = default;

    for meta in metas {
        match meta {
            Meta::NameValue(name_value) if name_value.path.is_ident("flavor") => {
                let Expr::Lit(expr_lit) = name_value.value else {
                    return Err(syn::Error::new_spanned(
                        name_value,
                        "flavor value must be a string literal",
                    ));
                };
                let Lit::Str(lit) = expr_lit.lit else {
                    return Err(syn::Error::new_spanned(
                        expr_lit,
                        "flavor value must be a string literal",
                    ));
                };
                flavor = match lit.value().as_str() {
                    "current_thread" => Flavor::CurrentThread,
                    "multi_thread" => Flavor::MultiThread,
                    _ => {
                        return Err(syn::Error::new_spanned(
                            lit,
                            "unsupported flavor; expected \"current_thread\" or \"multi_thread\"",
                        ));
                    }
                };
            }
            other => {
                return Err(syn::Error::new_spanned(
                    other,
                    "unsupported runtime attribute argument",
                ));
            }
        }
    }

    Ok(flavor)
}

fn builder_tokens(flavor: Flavor) -> proc_macro2::TokenStream {
    match flavor {
        Flavor::CurrentThread => {
            quote!(::fcp_async_core::runtime::Builder::new_current_thread())
        }
        Flavor::MultiThread => {
            quote!(::fcp_async_core::runtime::Builder::new_multi_thread())
        }
    }
}

fn expand_runtime_fn(
    args: TokenStream,
    input: TokenStream,
    default_flavor: Flavor,
    add_test_attr: bool,
) -> TokenStream {
    let flavor = match parse_flavor(args, default_flavor) {
        Ok(flavor) => flavor,
        Err(err) => return err.to_compile_error().into(),
    };

    let function = parse_macro_input!(input as ItemFn);
    let attrs = function.attrs;
    let vis = function.vis;
    let mut sig = function.sig;
    let block = function.block;

    if sig.asyncness.is_none() {
        return syn::Error::new_spanned(sig.fn_token, "runtime attribute requires async fn")
            .to_compile_error()
            .into();
    }

    sig.asyncness = None;
    let builder = builder_tokens(flavor);
    let maybe_test_attr = add_test_attr.then(|| quote!(#[test]));

    quote! {
        #(#attrs)*
        #maybe_test_attr
        #vis #sig {
            let runtime = #builder
                .enable_all()
                .build()
                .expect("failed to build fcp_async_core runtime");
            runtime.block_on(async move #block)
        }
    }
    .into()
}

/// `main` attribute backed by `fcp_async_core::runtime::Builder`.
#[proc_macro_attribute]
pub fn main(args: TokenStream, input: TokenStream) -> TokenStream {
    expand_runtime_fn(args, input, Flavor::MultiThread, false)
}

/// `test` attribute backed by `fcp_async_core::runtime::Builder`.
#[proc_macro_attribute]
pub fn test(args: TokenStream, input: TokenStream) -> TokenStream {
    expand_runtime_fn(args, input, Flavor::CurrentThread, true)
}
