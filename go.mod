module github.com/GhostN3xus/Huntsuite

go 1.21

require (
	github.com/gocolly/colly/v2 v2.1.0
	github.com/projectdiscovery/interactsh/pkg/client v0.0.0
)

require (
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/cobra v1.10.1 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
)

replace github.com/gocolly/colly/v2 => ./third_party/gocolly/colly/v2

replace github.com/projectdiscovery/interactsh/pkg/client => ./third_party/interactsh/pkg/client
