use quote::quote;
use proc_macro::TokenStream;
use syn::{Ident, Token, parse_macro_input};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;

pub(crate) struct MnemonicList<P: Parse>(pub Vec<P>);

impl<P: Parse> Parse for MnemonicList<P> {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(MnemonicList(
            Punctuated::<P, Token![,]>::parse_terminated(&input)?.into_iter().collect()
        ))
    }
}

pub(crate) struct Mnemonic {
    arrow: Option<Token![=>]>,
    name: Ident,
}

impl Parse for Mnemonic {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let lookahead = input.lookahead1();
        let arrow = if lookahead.peek(Token![=>]) {
            Some(input.parse()?)
        } else {
            None
        };

        Ok(Mnemonic {
            arrow,
            name: input.parse()?
        })
    }
}

// impl<'a, P: 'a + Parse> Iterator for MnemonicList<P> {
//     type Item = &'a P;

//     fn next(&mut self) -> Option<&P> {
//         self.0.iter().next()
//     }
// }

#[proc_macro]
pub fn mnemonic_search(input: TokenStream) -> TokenStream {
    let mnemonics = parse_macro_input!(input as MnemonicList<Mnemonic>).0;

    if mnemonics.len() == 0 {
        return quote!(0).into()
    }

    let has_specified_position = mnemonics.iter().find(|x| x.arrow.is_some()).is_some();

    let (set_hook_pos, mnemonics): (Vec<_>, Vec<_>) = if has_specified_position {
        mnemonics.into_iter()
            .map(|x| {
                (
                    x.arrow.map(|_| quote!{
                        hook_pos = pos;
                    }),

                    x.name
                )
            })
            .unzip()
    } else {
        // If no hook pos is specified, make it the first instruction
        let mut set_hook_pos = vec![Some(quote!{ hook_pos = pos; })];
        set_hook_pos.resize_with(mnemonics.len(), Default::default);

        (set_hook_pos, mnemonics.into_iter().map(|x| x.name).collect())
    };

    let mut return_hook_pos: Vec<Option<proc_macro2::TokenStream>> = (0..mnemonics.len() - 1).map(|_| None).collect();
    return_hook_pos.push(Some(quote!(
        return Some(hook_pos);
    )));

    let num = 0..;

    let expanded = quote! {
        (|| {
            let mut state = 0;
            let mut hook_pos = 0;

            #[allow(unreachable_code)]
            for (pos, instr) in TextIter::new() {
                state = match (state, instr) {
                    #(
                        (#num, aarch64_decode::Instr::#mnemonics { .. }) => {
                            #set_hook_pos
                            
                            #return_hook_pos

                            #num + 1
                        }
                     )*
                    _ => 0,
                };
            }

            None
        })()
    };

    expanded.into()
}
