int use_after_delete_read() { int *data = new int(1); delete data; return *data; }
