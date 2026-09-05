package cmd

import (
	"strconv"
	"strings"
)

// displayText makes an untrusted value safe to include in terminal-oriented
// output while preserving printable Unicode.
func displayText(value string) string {
	var output strings.Builder
	for _, character := range value {
		if character < ' ' || (character >= '\x7f' && character <= '\u009f') {
			escaped := strconv.QuoteRune(character)
			output.WriteString(escaped[1 : len(escaped)-1])
			continue
		}
		output.WriteRune(character)
	}
	return output.String()
}
