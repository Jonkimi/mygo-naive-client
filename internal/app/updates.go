package app

import (
	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/updater"
	"github.com/egoist/mygo/plugins/updater/native"
)

// Client updater function pointers, swappable for testing.
var (
	checkForClientUpdates    = updater.CheckForUpdates
	clientUpdateChecks       = updater.AutomaticChecks
	setClientUpdateChecks    = updater.SetAutomaticChecks
	clientUpdateDownloads    = updater.AutomaticDownloads
	setClientUpdateDownloads = updater.SetAutomaticDownloads
	lastClientUpdateCheck    = updater.LastCheck
)

func (a *app) initClientUpdater() {
	if a.headless {
		return
	}
	mygo.Use(native.New(updater.Options{
		Language: "zh-Hans",
	}))
}
