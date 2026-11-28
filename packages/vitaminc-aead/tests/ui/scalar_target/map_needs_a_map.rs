//! A map target reads a map with one leaf for each value. So one scalar does
//! not build it.

use std::collections::{BTreeMap, HashMap};

use vitaminc_aead::ScalarTarget;

fn opens_one_leaf<T: ScalarTarget>() {}

fn main() {
    opens_one_leaf::<HashMap<String, i64>>();
    opens_one_leaf::<BTreeMap<String, i64>>();
}
