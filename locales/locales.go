package locales

import (
	"os"
	"strings"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/i18n"
)

// Supported language codes.
const (
	LangSystem = "system"
	LangZhHans = "zh-Hans"
	LangEn     = "en"
)

// SupportedLanguages returns the list of language tags supported by the app.
func SupportedLanguages() []string {
	return []string{LangZhHans, LangEn}
}

// DetectSystemLang detects system locale from standard environment variables.
func DetectSystemLang() string {
	for _, env := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		val := os.Getenv(env)
		if val != "" {
			lower := strings.ToLower(val)
			if strings.HasPrefix(lower, "zh") {
				return LangZhHans
			}
		}
	}
	return LangEn
}

// ResolveLocale resolves a language code ("system", "zh-Hans", "en", or "")
// to a concrete BCP 47 language tag supported by the catalogs.
func ResolveLocale(lang string) string {
	switch lang {
	case LangZhHans:
		return LangZhHans
	case LangEn:
		return LangEn
	case LangSystem, "":
		if l := mygo.App.Locale(); l != "" {
			return l
		}
		if l := i18n.Locale(); l != "" {
			return l
		}
		return DetectSystemLang()
	default:
		return LangEn
	}
}
