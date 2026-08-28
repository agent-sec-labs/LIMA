int delete_then_reassign() { int *data = new int(1); delete data; data = new int(2); int result = *data; delete data; return result; }
