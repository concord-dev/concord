package scaffold_test

import "os"

func removeFileImpl(p string) error { return os.Remove(p) }
