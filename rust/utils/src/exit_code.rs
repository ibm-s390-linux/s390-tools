// SPDX-License-Identifier: MIT
//
// Copyright IBM Corp. 2024

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExitCodeVariantDoc {
    pub name: String,
    pub value: String,
    pub doc: String,
}

impl ExitCodeVariantDoc {
    pub fn new<N, V, D>(name: N, value: V, doc: D) -> Self
    where
        N: AsRef<str>,
        V: AsRef<str>,
        D: AsRef<str>,
    {
        Self {
            name: name.as_ref().to_string(),
            value: value.as_ref().to_string(),
            doc: doc.as_ref().to_string(),
        }
    }
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExitCodeDoc {
    pub doc: Option<String>,
    pub variants: Vec<ExitCodeVariantDoc>,
}

pub trait ExitCodeTrait {
    fn exit_code_doc() -> ExitCodeDoc;
}

pub fn docstring(attr: &str) -> Option<String> {
    if !attr.starts_with("doc = r\"") {
        return None;
    }
    let mut doc = attr
        .strip_prefix("doc = r\"")
        .unwrap()
        .strip_suffix('\"')
        .unwrap()
        .to_string();
    if doc.starts_with(' ') {
        doc = doc.strip_prefix(' ').unwrap().to_string();
    }
    Some(doc)
}

#[macro_export]
macro_rules! impl_exitcodetrait {
    ($(#[$attr:meta])* $vis:vis enum $name:ident $(<$($gen:ident),*>)? {
        $(
        $(#[$variantattr:meta])+ $variant:ident = $tvalue:literal
        ),* $(,)?
    }
    ) => {
        $(#[$attr])*
        $vis enum $name $(<$($gen),*>)? {
            $(
                $(#[$variantattr])+ $variant = $tvalue
            ),*
        }

        impl ExitCodeTrait for $(<$($gen),*>)? $name $(<$($gen),*>)? {
            fn exit_code_doc() -> $crate::ExitCodeDoc {
                let enum_doc_vec = [$(stringify!($attr)),*].into_iter().map($crate::docstring).filter_map(std::convert::identity).collect::<Vec<_>>();
                let enum_doc = (!enum_doc_vec.is_empty()).then_some(enum_doc_vec.join("\n"));
                let mut variants = vec![];
                $(
                    let name = stringify!($variant).to_string();
                    let value = stringify!($tvalue).to_string();
                    let docs: Vec<_> = [$(stringify!($variantattr)),+].into_iter().map($crate::docstring).filter_map(std::convert::identity).collect();
                    assert!(!docs.is_empty(), "Please add a docstring to enum variant '{name}' of '{}'", stringify!($name));
                    variants.push($crate::ExitCodeVariantDoc { name, value, doc: docs.join("\n")});
                )*
                    $crate::ExitCodeDoc {
                        doc: enum_doc,
                        variants,
                    }
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use crate::{exit_code::ExitCodeDoc, ExitCodeTrait, ExitCodeVariantDoc};

    #[test]
    fn test_impl_exitcodetrait_with_doc() {
        impl_exitcodetrait!(
            /// Program exit codes
            ///
            /// Multiline.
            #[repr(u8)]
            #[allow(unused)]
            #[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
            pub enum OwnExitCode {
                /// Program finished successfully
                ///
                /// Long description.
                Success = 0,
                /// Generic error
                #[default]
                GenericError = 1,
                /// Usage error
                UsageError = 2, // same exit code as used by `Clap` crate
            }
        );

        assert_eq!(
            OwnExitCode::exit_code_doc(),
            ExitCodeDoc {
                doc: Some("Program exit codes\n\nMultiline.".to_string()),
                variants: vec![
                    ExitCodeVariantDoc::new(
                        "Success",
                        "0",
                        "Program finished successfully\n\nLong description."
                    ),
                    ExitCodeVariantDoc::new("GenericError", "1", "Generic error"),
                    ExitCodeVariantDoc::new("UsageError", "2", "Usage error")
                ]
            }
        );

        assert_eq!(OwnExitCode::default(), OwnExitCode::GenericError);
    }

    #[test]
    fn test_impl_exitcodetrait_without_doc() {
        impl_exitcodetrait!(
            #[repr(u8)]
            #[allow(unused)]
            #[derive(Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
            pub enum OwnExitCode {
                /// Program finished successfully
                ///
                /// Long description.
                Success = 0,
                /// Generic error
                #[default]
                GenericError = 1,
                /// Usage error
                UsageError = 2, // same exit code as used by `Clap` crate
            }
        );

        assert_eq!(
            OwnExitCode::exit_code_doc(),
            ExitCodeDoc {
                doc: None,
                variants: vec![
                    ExitCodeVariantDoc::new(
                        "Success",
                        "0",
                        "Program finished successfully\n\nLong description."
                    ),
                    ExitCodeVariantDoc::new("GenericError", "1", "Generic error"),
                    ExitCodeVariantDoc::new("UsageError", "2", "Usage error")
                ]
            }
        );

        assert_eq!(OwnExitCode::default(), OwnExitCode::GenericError);
    }
}
