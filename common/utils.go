package common

import "strings"

func NormalizeCountry(s string) string {
	return strings.ToUpper(s)
}

func NormalizeURI(s string) string {
	return strings.ToLower(s)
}
