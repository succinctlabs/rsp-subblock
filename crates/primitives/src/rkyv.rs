use reth_primitives::Bloom;
use revm_primitives::B256;

#[derive(
    Clone,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
#[rkyv(remote = B256)]
#[rkyv(archived = ArchivedB256)]
#[rkyv(attr(derive(Eq, PartialEq, Hash)))]
pub struct B256Def(pub [u8; 32]);

impl From<B256Def> for B256 {
    fn from(value: B256Def) -> Self {
        B256::new(value.0)
    }
}

pub struct BloomDef(pub [u8; 256]);

impl From<BloomDef> for Bloom {
    fn from(value: BloomDef) -> Self {
        Bloom::new(value.0)
    }
}
