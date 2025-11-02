module github.com/GhostN3xus/Huntsuite

go 1.21

require (
    github.com/gocolly/colly/v2 v2.1.0
    github.com/projectdiscovery/interactsh/pkg/client v0.0.0
)

replace github.com/gocolly/colly/v2 => ./third_party/gocolly/colly/v2
replace github.com/projectdiscovery/interactsh/pkg/client => ./third_party/interactsh/pkg/client

