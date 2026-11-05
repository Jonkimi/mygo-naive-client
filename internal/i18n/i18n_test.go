package i18n

import (
	"reflect"
	"testing"
)

func TestCatalogCompleteCoverage(t *testing.T) {
	// Ensure both ZhHans and En define non-empty strings for all string fields in Catalog
	for _, tc := range []struct {
		name string
		cat  *Catalog
	}{
		{"zh-Hans", ZhHans},
		{"en", En},
	} {
		t.Run(tc.name, func(t *testing.T) {
			val := reflect.ValueOf(tc.cat).Elem()
			typ := val.Type()
			for i := 0; i < val.NumField(); i++ {
				field := typ.Field(i)
				fieldVal := val.Field(i)
				if field.Type.Kind() == reflect.String {
					str := fieldVal.String()
					if str == "" {
						t.Errorf("Catalog %s has empty string field: %s", tc.name, field.Name)
					}
				}
			}
		})
	}
}

func TestForSelection(t *testing.T) {
	if For(LangZhHans) != ZhHans {
		t.Errorf("For(LangZhHans) did not return ZhHans")
	}
	if For(LangEn) != En {
		t.Errorf("For(LangEn) did not return En")
	}
	sys := For(LangSystem)
	if sys != ZhHans && sys != En {
		t.Errorf("For(LangSystem) returned unknown catalog")
	}
}

func TestFormatters(t *testing.T) {
	zhRunning := ZhHans.RunningCount(2, 5)
	if zhRunning != "本地服务 (2/5 运行中)" {
		t.Errorf("ZhHans.RunningCount unexpected: %q", zhRunning)
	}

	enRunning := En.RunningCount(2, 5)
	if enRunning != "Services (2/5 running)" {
		t.Errorf("En.RunningCount unexpected: %q", enRunning)
	}
}
