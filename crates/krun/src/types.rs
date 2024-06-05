use std::num::ParseIntError;
use std::str::FromStr;

#[derive(Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Debug)]
pub struct MiB(u32);

impl From<u32> for MiB {
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl FromStr for MiB {
    type Err = ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(u32::from_str(s)?.into())
    }
}

impl From<MiB> for u32 {
    fn from(value: MiB) -> Self {
        value.0
    }
}
