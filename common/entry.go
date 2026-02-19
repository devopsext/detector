package common

// Entry — базовый интерфейс любого объекта мониторинга.
//
// Примеры EntryKey():
//   домены:   "domain.com"          (NormalizeURI(URI) если Key пустой)
//   BP:       "deposit"             (из поля Key)
//   Frontend: "web-trader:panel"    (из поля Key)
//
// Методы называются EntryKey/EntryIdent (не Key/Ident): Go запрещает одновременно
// иметь поле Key string и метод Key() string в одной структуре.
type Entry interface {
	EntryKey() string   // primary key группировки и триггеров
	EntryIdent() string // human-readable (EntryKey + [sorted countries])
}

// SourceEntry — сущность из источника данных (домен, BP, Frontend и др.)
type SourceEntry interface {
	Entry
	EntryCountries() []string
	EntryDisabled() bool
	EntryDetectors() []string
}

// ObserveEntry — сущность после наблюдения (с probability по странам).
type ObserveEntry interface {
	Entry
	EntryObserveCountries() ObserveCountries // map[string]*ObserveProbability
}

// VerifyEntry — сущность после верификации (с флагами и вероятностями по странам).
type VerifyEntry interface {
	Entry
	EntryVerifyCountries() VerifyCountries // map[string]*VerifyStatus
}
