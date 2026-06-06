package main

import (
	"os"

	"github.com/d0cd/dispatcher/internal/cli"
)

func main() {
	if err := cli.Execute(); err != nil {
		os.Exit(1)
	}
}
