use std::{fmt, str::FromStr};

/// URI parsed through the shared URL parser with deterministic display output.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SafeUri(url::Url);

impl SafeUri {
    /// Return the URI scheme.
    #[must_use]
    pub fn scheme(&self) -> &str {
        self.0.scheme()
    }

    /// Return the host component when the URI shape carries one.
    #[must_use]
    pub fn host(&self) -> Option<&str> {
        self.0.host_str()
    }

    /// Return the path component.
    #[must_use]
    pub fn path(&self) -> &str {
        self.0.path()
    }

    /// Return the raw query component without the leading `?`.
    #[must_use]
    pub fn query(&self) -> Option<&str> {
        self.0.query()
    }

    /// Return the parsed URL object.
    #[must_use]
    pub fn as_url(&self) -> &url::Url {
        &self.0
    }
}

impl FromStr for SafeUri {
    type Err = url::ParseError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        url::Url::parse(input).map(Self)
    }
}

impl fmt::Display for SafeUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.as_str())
    }
}

impl AsRef<url::Url> for SafeUri {
    fn as_ref(&self) -> &url::Url {
        self.as_url()
    }
}

impl From<SafeUri> for url::Url {
    fn from(value: SafeUri) -> Self {
        value.0
    }
}
