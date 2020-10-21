use quote::quote;
use proc_macro::{ TokenStream };
use syn::{Ident, Token, parse_macro_input};
use syn::parse::{ Parse, ParseStream };
use syn::punctuated::Punctuated;

pub(crate) struct MnemonicList<P: Parse>(pub Vec<P>);

impl<P: Parse> Parse for MnemonicList<P> {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        Ok(MnemonicList(
            Punctuated::<P, Token![,]>::parse_terminated(&input)?.into_iter().collect()
        ))
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
    let mnemonics = parse_macro_input!(input as MnemonicList<Ident>);

    let expanded = quote! {
        (|| {
            let mut state = 0;
            let mut hook_pos = 0;

            for (pos, instr) in TextIter::new() {
                state = match (state, instr) {
                    #(#mnemonics.0.iter()),* {

                    }
                };
            }

            // Temp
            Some(hook_pos)
        })
    };

    expanded.into()
}