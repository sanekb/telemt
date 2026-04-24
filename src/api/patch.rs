use serde::Deserialize;

/// Three-state field for JSON Merge Patch semantics on the `PATCH /v1/users/{user}`
/// endpoint.
///
/// `Unchanged` is produced when the JSON body omits the field entirely and tells the
/// handler to leave the corresponding configuration entry untouched. `Remove` is
/// produced when the JSON body sets the field to `null` and instructs the handler to
/// drop the entry from the corresponding access HashMap. `Set` carries an explicit
/// new value, including zero, which is preserved verbatim in the configuration.
#[derive(Debug)]
pub(super) enum Patch<T> {
    Unchanged,
    Remove,
    Set(T),
}

impl<T> Default for Patch<T> {
    fn default() -> Self {
        Self::Unchanged
    }
}

/// Serde deserializer adapter for fields that follow JSON Merge Patch semantics.
///
/// Pair this with `#[serde(default, deserialize_with = "patch_field")]` on a
/// `Patch<T>` field. An omitted field falls back to `Patch::Unchanged` via
/// `Default`; an explicit JSON `null` becomes `Patch::Remove`; any other value
/// becomes `Patch::Set(v)`.
pub(super) fn patch_field<'de, D, T>(deserializer: D) -> Result<Patch<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(|opt| match opt {
        Some(value) => Patch::Set(value),
        None => Patch::Remove,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct Holder {
        #[serde(default, deserialize_with = "patch_field")]
        value: Patch<u64>,
    }

    fn parse(json: &str) -> Holder {
        serde_json::from_str(json).expect("valid json")
    }

    #[test]
    fn omitted_field_yields_unchanged() {
        let h = parse("{}");
        assert!(matches!(h.value, Patch::Unchanged));
    }

    #[test]
    fn explicit_null_yields_remove() {
        let h = parse(r#"{"value": null}"#);
        assert!(matches!(h.value, Patch::Remove));
    }

    #[test]
    fn explicit_value_yields_set() {
        let h = parse(r#"{"value": 42}"#);
        assert!(matches!(h.value, Patch::Set(42)));
    }

    #[test]
    fn explicit_zero_yields_set_zero() {
        let h = parse(r#"{"value": 0}"#);
        assert!(matches!(h.value, Patch::Set(0)));
    }
}
