package common

// Entry is the base interface for any monitoring object.
//
// EntryKey() examples:
//
//	domains:   "domain.com"          (NormalizeURI(URI) when Key is empty)
//	BP:        "deposit"             (from Key field)
//	Frontend:  "web-trader:panel"    (from Key field)
//
// Methods are named EntryKey/EntryIdent (not Key/Ident) because Go does not allow
// a struct to have both a field `Key string` and a method `Key() string`.
type Entry interface {
	EntryKey() string   // primary key used for grouping and triggers
	EntryIdent() string // human-readable identifier (EntryKey + [sorted countries])
}

// SourceEntry represents an entity from a data source (domain, BP, Frontend, etc.)
type SourceEntry interface {
	Entry
	EntryCountries() []string
	EntryDisabled() bool
	EntryDetectors() []string
}

// ObserveEntry represents an entity after observation (with per-country probabilities).
type ObserveEntry interface {
	Entry
	EntryObserveCountries() ObserveCountries // map[string]*ObserveProbability
}

// VerifyEntry represents an entity after verification (with per-country flags and probabilities).
type VerifyEntry interface {
	Entry
	EntryVerifyCountries() VerifyCountries // map[string]*VerifyStatus
}
