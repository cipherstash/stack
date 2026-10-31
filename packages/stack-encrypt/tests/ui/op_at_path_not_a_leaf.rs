//! `AtPath` applies a leaf operator at a path: containment compares whole
//! documents, and an accessor already has a path, so neither is an
//! operator under `AtPath`.
use stack_encrypt::op;

fn operator<Op: op::Operator>(_: Op) {}

fn main() {
    operator(op::AtPath(op::Contains));
    operator(op::AtPath(op::AtPath(op::Eq)));
}
