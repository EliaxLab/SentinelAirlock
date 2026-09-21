package cli

import "github.com/EliaxLab/SentinelAirlock/internal/index"

func refreshIndex() {
	store, err := index.Rebuild(".airlock/runs")
	if err != nil {
		return
	}
	_ = index.Save(index.DefaultPath(), store)
}
