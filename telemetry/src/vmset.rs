use crate::{Vm, VmId};
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};

/// The current set of known VMs. Discovery writes it; samplers read it.
#[derive(Debug, Clone, Default)]
pub struct VmSet(Arc<RwLock<BTreeMap<VmId, Vm>>>);

impl VmSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn snapshot(&self) -> Vec<Vm> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).values().cloned().collect()
    }

    pub fn get(&self, id: &VmId) -> Option<Vm> {
        self.0.read().unwrap_or_else(|e| e.into_inner()).get(id).cloned()
    }

    pub fn insert(&self, vm: Vm) {
        self.0.write().unwrap_or_else(|e| e.into_inner()).insert(vm.id.clone(), vm);
    }

    pub fn remove(&self, id: &VmId) -> Option<Vm> {
        self.0.write().unwrap_or_else(|e| e.into_inner()).remove(id)
    }

    pub fn len(&self) -> usize {
        self.0.read().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
