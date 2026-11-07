//! Procedural macros for [`permission_proc`](https://docs.rs/permission_proc).
//!
//! Depend on `permission_proc` instead of this crate: it re-exports the
//! macro together with the traits the generated code relies on.

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::{quote, quote_spanned, ToTokens};
use syn::{
    parenthesized,
    parse::{Parse, ParseStream},
    parse_macro_input,
    punctuated::Punctuated,
    spanned::Spanned,
    Error, FnArg, GenericArgument, Ident, ItemFn, LitBool, LitStr, Pat, PathArguments, ReturnType,
    Signature, Token, Type,
};

/// Guards a function with a permission check.
///
/// See the [`permission_proc` documentation](https://docs.rs/permission_proc)
/// for the full syntax.
#[proc_macro_attribute]
pub fn permission(attr: TokenStream, item: TokenStream) -> TokenStream {
    let args = parse_macro_input!(attr as Args);
    let function = parse_macro_input!(item as ItemFn);
    expand(args, function)
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Parsed form of `any(...)`, `all(...)` or a string literal.
enum Requirement {
    Permission(LitStr),
    Any(Vec<Requirement>),
    All(Vec<Requirement>),
}

impl Parse for Requirement {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(LitStr) {
            let permission: LitStr = input.parse()?;
            if permission.value().is_empty() {
                return Err(Error::new(
                    permission.span(),
                    "permission must not be empty",
                ));
            }
            return Ok(Requirement::Permission(permission));
        }

        let lookahead = input.lookahead1();
        if !lookahead.peek(Ident) {
            return Err(Error::new(
                input.span(),
                "expected a permission string, `any(...)` or `all(...)`",
            ));
        }
        let combinator: Ident = input.parse()?;
        let make: fn(Vec<Requirement>) -> Requirement = match combinator.to_string().as_str() {
            "any" => Requirement::Any,
            "all" => Requirement::All,
            _ => {
                return Err(Error::new(
                    combinator.span(),
                    "expected a permission string, `any(...)` or `all(...)`",
                ))
            }
        };

        let content;
        parenthesized!(content in input);
        let items = Punctuated::<Requirement, Token![,]>::parse_terminated(&content)?;
        if items.is_empty() {
            return Err(Error::new(
                combinator.span(),
                format!("`{combinator}(...)` needs at least one permission"),
            ));
        }
        Ok(make(items.into_iter().collect()))
    }
}

impl Requirement {
    fn to_tokens(&self, krate: &TokenStream2) -> TokenStream2 {
        match self {
            Requirement::Permission(permission) => {
                quote!(#krate::Requirement::Permission(#permission))
            }
            Requirement::Any(items) => {
                let items = items.iter().map(|r| r.to_tokens(krate));
                quote!(#krate::Requirement::Any(&[#(#items),*]))
            }
            Requirement::All(items) => {
                let items = items.iter().map(|r| r.to_tokens(krate));
                quote!(#krate::Requirement::All(&[#(#items),*]))
            }
        }
    }
}

/// Everything inside `#[permission(...)]`.
struct Args {
    requirement: Requirement,
    claims: Option<Ident>,
    result: Option<bool>,
    krate: Option<syn::Path>,
}

impl Parse for Args {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.is_empty() {
            return Err(Error::new(
                Span::call_site(),
                "missing permission, e.g. `#[permission(\"posts:read\")]`",
            ));
        }
        let mut args = Args {
            requirement: input.parse()?,
            claims: None,
            result: None,
            krate: None,
        };

        while !input.is_empty() {
            input.parse::<Token![,]>()?;
            if input.is_empty() {
                break;
            }

            if input.peek(Token![crate]) {
                let key = input.parse::<Token![crate]>()?;
                input.parse::<Token![=]>()?;
                set_once(&mut args.krate, input.parse()?, key.span, "crate")?;
                continue;
            }

            let key: Ident = input.parse()?;
            input.parse::<Token![=]>()?;
            match key.to_string().as_str() {
                "claims" => set_once(&mut args.claims, input.parse()?, key.span(), "claims")?,
                "result" => {
                    let value: LitBool = input.parse()?;
                    set_once(&mut args.result, value.value, key.span(), "result")?;
                }
                other => {
                    return Err(Error::new(
                        key.span(),
                        format!("unknown option `{other}`; expected `claims`, `result` or `crate`"),
                    ))
                }
            }
        }
        Ok(args)
    }
}

fn set_once<T>(slot: &mut Option<T>, value: T, span: Span, name: &str) -> syn::Result<()> {
    if slot.is_some() {
        return Err(Error::new(span, format!("`{name}` is set more than once")));
    }
    *slot = Some(value);
    Ok(())
}

fn expand(args: Args, mut function: ItemFn) -> syn::Result<TokenStream2> {
    let krate = args
        .krate
        .as_ref()
        .map_or_else(|| quote!(::permission_proc), ToTokens::to_token_stream);
    let claims = find_claims(&mut function.sig, args.claims)?;
    let returns_result = args
        .result
        .unwrap_or_else(|| returns_result(&function.sig.output));

    let requirement = args.requirement.to_tokens(&krate);
    let rejection = quote!(::core::convert::Into::into(__permission_proc_rejection));
    let early_return = if returns_result {
        quote!(return ::core::result::Result::Err(#rejection);)
    } else {
        quote!(return #rejection;)
    };
    // Spanned on the claims binding so a missing `Permissions` impl is
    // reported on the argument rather than on the whole attribute.
    let check = quote_spanned! {claims.span()=>
        #claims.__permission_proc_check(&__PERMISSION_PROC_REQUIREMENT)
    };

    let ItemFn {
        attrs,
        vis,
        sig,
        block,
    } = function;

    Ok(quote! {
        #(#attrs)*
        #vis #sig {
            {
                #[allow(unused_imports)]
                use #krate::__private::PermissionProcExt as _;
                const __PERMISSION_PROC_REQUIREMENT: #krate::Requirement = #requirement;
                if let ::core::option::Option::Some(__permission_proc_rejection) = #check {
                    #early_return
                }
            }
            #block
        }
    })
}

/// Locates the binding that holds the claims and strips `#[claims]` markers.
fn find_claims(sig: &mut Signature, explicit: Option<Ident>) -> syn::Result<Ident> {
    let mut marked = None;
    for arg in &mut sig.inputs {
        let FnArg::Typed(pat_type) = arg else {
            continue;
        };
        let before = pat_type.attrs.len();
        pat_type
            .attrs
            .retain(|attr| !attr.path().is_ident("claims"));
        if pat_type.attrs.len() == before {
            continue;
        }
        if marked.is_some() {
            return Err(Error::new(
                pat_type.span(),
                "only one argument can be marked with `#[claims]`",
            ));
        }
        marked = Some(pat_type.pat.clone());
    }

    match (explicit, marked) {
        (Some(name), Some(pat)) => Err(Error::new(
            pat.span(),
            format!("claims argument is given twice: `claims = {name}` and `#[claims]`; keep one"),
        )),
        (Some(name), None) => Ok(name),
        (None, Some(pat)) => binding_of(&pat),
        (None, None) => {
            let mut candidates = sig.inputs.iter().filter_map(|arg| match arg {
                FnArg::Typed(pat_type) if mentions_claims(&pat_type.ty) => Some(pat_type),
                _ => None,
            });
            match (candidates.next(), candidates.next()) {
                (Some(only), None) => binding_of(&only.pat),
                (Some(_), Some(second)) => Err(Error::new(
                    second.span(),
                    "several arguments look like claims; mark one with `#[claims]` \
                     or use `#[permission(..., claims = name)]`",
                )),
                (None, _) => Err(Error::new(
                    sig.ident.span(),
                    format!(
                        "cannot find the claims argument of `{}`; add an argument whose type \
                         ends in `Claims`, mark one with `#[claims]`, \
                         or use `#[permission(..., claims = name)]`",
                        sig.ident
                    ),
                )),
            }
        }
    }
}

/// Returns the identifier bound by `pat`.
fn binding_of(pat: &Pat) -> syn::Result<Ident> {
    match pat {
        Pat::Ident(pat_ident) if pat_ident.subpat.is_none() => Ok(pat_ident.ident.clone()),
        Pat::TupleStruct(tuple) if tuple.elems.len() == 1 => binding_of(&tuple.elems[0]),
        Pat::Paren(paren) => binding_of(&paren.pat),
        Pat::Wild(_) => Err(Error::new(
            pat.span(),
            "the claims argument is ignored with `_`; give it a name, e.g. `claims`",
        )),
        _ => Err(Error::new(
            pat.span(),
            "cannot read the claims from this pattern; bind it to a name, \
             e.g. `claims: Claims` or `Extension(claims): Extension<Claims>`",
        )),
    }
}

/// Whether `ty` mentions a type whose last path segment ends in `Claims`.
fn mentions_claims(ty: &Type) -> bool {
    match ty {
        Type::Path(type_path) => type_path.path.segments.iter().any(|segment| {
            segment.ident.to_string().ends_with("Claims")
                || match &segment.arguments {
                    PathArguments::AngleBracketed(generics) => {
                        generics.args.iter().any(|arg| match arg {
                            GenericArgument::Type(inner) => mentions_claims(inner),
                            _ => false,
                        })
                    }
                    _ => false,
                }
        }),
        Type::Reference(reference) => mentions_claims(&reference.elem),
        Type::Paren(paren) => mentions_claims(&paren.elem),
        Type::Group(group) => mentions_claims(&group.elem),
        _ => false,
    }
}

/// Whether the declared return type is written as `...::Result<..>`.
fn returns_result(output: &ReturnType) -> bool {
    match output {
        ReturnType::Type(_, ty) => match &**ty {
            Type::Path(type_path) => type_path
                .path
                .segments
                .last()
                .is_some_and(|segment| segment.ident == "Result"),
            _ => false,
        },
        ReturnType::Default => false,
    }
}
