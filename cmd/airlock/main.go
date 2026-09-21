package main

import "github.com/EliaxLab/SentinelAirlock/internal/cli"

var version = "dev"
var commit = "none"
var buildDate = "unknown"

func main() {
	cli.Version = version
	cli.Commit = commit
	cli.BuildDate = buildDate
	cli.Execute()
}
