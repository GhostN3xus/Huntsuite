package logging

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// ProgressBar represents a progress tracking system for scans
type ProgressBar struct {
	mu          sync.Mutex
	writer      io.Writer
	total       int
	current     int
	description string
	startTime   time.Time
	width       int
	color       bool
	enabled     bool
	lastLine    string
	stats       ProgressStats
}

// ProgressStats holds statistics for the progress bar
type ProgressStats struct {
	RequestsSent      int
	FindingsFound     int
	ErrorsEncountered int
	CurrentModule     string
}

// NewProgressBar creates a new progress bar
func NewProgressBar(writer io.Writer, total int, description string, color bool, enabled bool) *ProgressBar {
	return &ProgressBar{
		writer:      writer,
		total:       total,
		current:     0,
		description: description,
		startTime:   time.Now(),
		width:       50,
		color:       color,
		enabled:     enabled,
		stats:       ProgressStats{},
	}
}

// Increment increments the progress by one
func (p *ProgressBar) Increment() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.current < p.total {
		p.current++
	}
	p.stats.RequestsSent++
	p.render()
}

// SetCurrent sets the current progress value
func (p *ProgressBar) SetCurrent(current int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = current
	p.render()
}

// IncrementFindings increments the findings counter
func (p *ProgressBar) IncrementFindings() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.FindingsFound++
	p.render()
}

// IncrementErrors increments the errors counter
func (p *ProgressBar) IncrementErrors() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.ErrorsEncountered++
	p.render()
}

// SetModule sets the current scanning module
func (p *ProgressBar) SetModule(module string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats.CurrentModule = module
	p.render()
}

// Finish completes the progress bar
func (p *ProgressBar) Finish() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.current = p.total
	p.render()
	fmt.Fprintln(p.writer) // New line after completion
}

// render draws the progress bar
func (p *ProgressBar) render() {
	if !p.enabled {
		return
	}

	// Clear previous line
	if p.lastLine != "" {
		fmt.Fprintf(p.writer, "\r%s\r", strings.Repeat(" ", len(p.lastLine)))
	}

	percentage := float64(p.current) / float64(p.total) * 100
	if p.total == 0 {
		percentage = 0
	}

	// Calculate bar
	filled := int(float64(p.width) * float64(p.current) / float64(p.total))
	if filled > p.width {
		filled = p.width
	}

	// Colors
	green := ""
	yellow := ""
	cyan := ""
	reset := ""
	bold := ""
	if p.color {
		green = "\033[32m"
		yellow = "\033[33m"
		cyan = "\033[36m"
		reset = "\033[0m"
		bold = "\033[1m"
	}

	// Build bar
	bar := strings.Repeat("█", filled) + strings.Repeat("░", p.width-filled)

	// Calculate ETA
	elapsed := time.Since(p.startTime)
	var eta time.Duration
	if p.current > 0 {
		eta = time.Duration(float64(elapsed) / float64(p.current) * float64(p.total-p.current))
	}

	// Build status line
	statusLine := fmt.Sprintf("%s%s%s [%s%s%s] %s%.1f%%%s | %s%d%s/%s%d%s",
		bold, p.description, reset,
		green, bar, reset,
		yellow, percentage, reset,
		cyan, p.current, reset,
		bold, p.total, reset,
	)

	// Add statistics
	statusLine += fmt.Sprintf(" | 🔍 %s%d%s 🚨 %s%d%s ❌ %s%d%s",
		cyan, p.stats.RequestsSent, reset,
		green, p.stats.FindingsFound, reset,
		yellow, p.stats.ErrorsEncountered, reset,
	)

	// Add module if set
	if p.stats.CurrentModule != "" {
		statusLine += fmt.Sprintf(" | Module: %s%s%s", bold, p.stats.CurrentModule, reset)
	}

	// Add ETA if available
	if p.current > 0 && p.current < p.total {
		statusLine += fmt.Sprintf(" | ETA: %s", formatDuration(eta))
	}

	// Add elapsed time
	statusLine += fmt.Sprintf(" | Time: %s", formatDuration(elapsed))

	p.lastLine = statusLine
	fmt.Fprint(p.writer, statusLine)
}

// formatDuration formats a duration in a human-readable way
func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
}

// UpdateStats updates all statistics at once
func (p *ProgressBar) UpdateStats(stats ProgressStats) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stats = stats
	p.render()
}

// GetStats returns the current statistics
func (p *ProgressBar) GetStats() ProgressStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}
