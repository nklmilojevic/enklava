package main

import (
	"os"

	"github.com/nklmilojevic/enklava/internal/cli"
	"github.com/nklmilojevic/enklava/internal/enklava"
)

func main() {
	t := enklava.FromEnv()
	if enklava.InsideAgent("keys") {
		os.Exit(t.PrintAgentKeys())
	}
	os.Exit(cli.Execute(t))
}
