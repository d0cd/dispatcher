package main

import (
	"fmt"
	"os"

	"github.com/d0cd/dispatcher/internal/cli"
)

func main() {
	// Tighten the file-creation mask so every os.OpenFile/os.WriteFile that
	// doesn't pass an explicit-perm flag still produces a 0600 file rather
	// than inheriting whatever loose umask the parent shell set (`umask 022`
	// is common; `umask 0` exists). Every sensitive write in dispatcher
	// already passes 0600 explicitly, but this is belt-and-braces against
	// any future caller that forgets.
	tightenFileMask()

	code, message := cli.ResolveExitError(cli.Execute())
	if message != "" {
		fmt.Fprintln(os.Stderr, "Error:", message)
	}
	os.Exit(code)
}
