//! Proc-macro wrappers for `fcp-async-core` runtime attributes.

#![forbid(unsafe_code)]

use proc_macro::TokenStream;
use quote::quote;
use syn::parse::Parser;
use syn::{Expr, ItemFn, Lit, Meta};

#[derive(Clone, Copy, Debug)]
enum Flavor {
    CurrentThread,
    MultiThread,
}

fn parse_flavor(args: proc_macro2::TokenStream, default: Flavor) -> syn::Result<Flavor> {
    let metas =
        syn::punctuated::Punctuated::<Meta, syn::Token![,]>::parse_terminated.parse2(args)?;
    let mut flavor = default;
    let mut seen_flavor = false;

    for meta in metas {
        match meta {
            Meta::NameValue(name_value) if name_value.path.is_ident("flavor") => {
                if seen_flavor {
                    return Err(syn::Error::new_spanned(
                        name_value,
                        "duplicate flavor argument",
                    ));
                }
                seen_flavor = true;
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

fn validate_runtime_signature(sig: &syn::Signature) -> syn::Result<()> {
    if sig.asyncness.is_none() {
        return Err(syn::Error::new_spanned(
            sig.fn_token,
            "runtime attribute requires async fn",
        ));
    }

    if !sig.generics.params.is_empty() || sig.generics.where_clause.is_some() {
        return Err(syn::Error::new_spanned(
            &sig.generics,
            "runtime attribute does not support generic parameters",
        ));
    }

    if !sig.inputs.is_empty() {
        return Err(syn::Error::new_spanned(
            &sig.inputs,
            "runtime attribute function must not accept arguments",
        ));
    }

    if let Some(constness) = sig.constness {
        return Err(syn::Error::new_spanned(
            constness,
            "runtime attribute does not support const fn",
        ));
    }

    if let Some(unsafety) = sig.unsafety {
        return Err(syn::Error::new_spanned(
            unsafety,
            "runtime attribute does not support unsafe fn",
        ));
    }

    if let Some(abi) = &sig.abi {
        return Err(syn::Error::new_spanned(
            abi,
            "runtime attribute does not support extern fn",
        ));
    }

    if let Some(variadic) = &sig.variadic {
        return Err(syn::Error::new_spanned(
            variadic,
            "runtime attribute does not support variadic functions",
        ));
    }

    Ok(())
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
    args: proc_macro2::TokenStream,
    input: proc_macro2::TokenStream,
    default_flavor: Flavor,
    add_test_attr: bool,
) -> syn::Result<proc_macro2::TokenStream> {
    let flavor = parse_flavor(args, default_flavor)?;
    let function = syn::parse2::<ItemFn>(input)?;
    let attrs = function.attrs;
    let vis = function.vis;
    let mut sig = function.sig;
    let block = function.block;

    validate_runtime_signature(&sig)?;

    sig.asyncness = None;
    let builder = builder_tokens(flavor);
    let maybe_test_attr = add_test_attr.then(|| quote!(#[test]));

    Ok(quote! {
        #(#attrs)*
        #maybe_test_attr
        #vis #sig {
            let runtime = #builder
                .enable_all()
                .build()
                .expect("failed to build fcp_async_core runtime");
            runtime.block_on(async move #block)
        }
    })
}

/// `main` attribute backed by `fcp_async_core::runtime::Builder`.
#[proc_macro_attribute]
pub fn main(args: TokenStream, input: TokenStream) -> TokenStream {
    expand_runtime_fn(args.into(), input.into(), Flavor::MultiThread, false)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

/// `test` attribute backed by `fcp_async_core::runtime::Builder`.
#[proc_macro_attribute]
pub fn test(args: TokenStream, input: TokenStream) -> TokenStream {
    expand_runtime_fn(args.into(), input.into(), Flavor::CurrentThread, true)
        .unwrap_or_else(|err| err.to_compile_error())
        .into()
}

#[cfg(test)]
mod tests {
    use super::{Flavor, expand_runtime_fn, parse_flavor, validate_runtime_signature};
    use quote::quote;
    use syn::ItemFn;

    #[test]
    fn parse_flavor_rejects_duplicate_argument() {
        let err = parse_flavor(
            quote!(flavor = "current_thread", flavor = "multi_thread"),
            Flavor::CurrentThread,
        )
        .expect_err("duplicate flavor should be rejected");

        assert!(err.to_string().contains("duplicate flavor"));
    }

    #[test]
    fn validate_signature_rejects_arguments() {
        let function: ItemFn = syn::parse2(quote!(
            async fn subject(arg: u32) {}
        ))
        .expect("function should parse");

        let err = validate_runtime_signature(&function.sig)
            .expect_err("functions with arguments should be rejected");
        assert!(err.to_string().contains("must not accept arguments"));
    }

    #[test]
    fn validate_signature_rejects_unsafe() {
        let function: ItemFn = syn::parse2(quote!(
            async unsafe fn subject() {}
        ))
        .expect("function should parse");

        let err =
            validate_runtime_signature(&function.sig).expect_err("unsafe fn should be rejected");
        assert!(err.to_string().contains("unsafe fn"));
    }

    #[test]
    fn expand_runtime_fn_adds_test_attribute() {
        let expanded = expand_runtime_fn(
            quote!(flavor = "current_thread"),
            quote!(
                async fn sample() {
                    assert_eq!(2 + 2, 4);
                }
            ),
            Flavor::CurrentThread,
            true,
        )
        .expect("expansion should succeed")
        .to_string();

        assert!(expanded.contains("# [test]"));
        assert!(expanded.contains("Builder :: new_current_thread"));
        assert!(expanded.contains("runtime . block_on"));
    }
}
