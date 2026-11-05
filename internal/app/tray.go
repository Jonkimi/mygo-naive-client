package app

import (
	"fmt"
	"runtime"

	"github.com/egoist/mygo"

	"naive-client/internal/runner"
)

func (a *app) applyAppIconPolicy() {
	if a.headless {
		return
	}
	mode := a.state.AppIcon
	showDock := mode != appIconMenubar
	showTray := mode != appIconDock

	if runtime.GOOS == "darwin" {
		if showDock {
			mygo.App.SetActivationPolicy(mygo.ActivationPolicyRegular)
		} else {
			mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
		}
	}

	if showTray {
		a.ensureTray()
	} else {
		a.destroyTray()
	}
}

func (a *app) ensureTray() {
	if a.headless {
		return
	}
	if a.tray != nil {
		a.rebuildTrayMenu()
		return
	}
	isTemplate := runtime.GOOS == "darwin"
	t, err := mygo.NewTray(mygo.TrayOptions{
		ID:             "naive-client.tray",
		Icon:           trayIconBytes(isTemplate),
		IconIsTemplate: isTemplate,
		ToolTip:        "NaiveClient",
		Menu:           a.buildTrayMenu(),
	})
	if err != nil {
		return
	}
	t.OnClick(func() {
		if runtime.GOOS != "darwin" {
			a.showMainWindow()
		}
	})
	a.tray = t
}

func (a *app) destroyTray() {
	if a.tray == nil {
		return
	}
	a.tray.Destroy()
	a.tray = nil
}

func (a *app) rebuildTrayMenu() {
	if a.tray == nil {
		return
	}
	a.tray.SetMenu(a.buildTrayMenu())
}

func (a *app) buildTrayMenu() *mygo.Menu {
	cat := a.catalog()
	var items []*mygo.MenuItem

	items = append(items, &mygo.MenuItem{
		Label: cat.TrayShow(),
		Click: func(*mygo.MenuItem, *mygo.Window) {
			a.showMainWindow()
		},
	})

	verLabel := cat.CoreVersionLabel() + ": " + cat.CoreNotInstalled()
	if a.localVersion != "" {
		verLabel = cat.CoreVersionLabel() + ": " + a.localVersion
	}
	if a.hasUpdate && a.latestRelease != nil {
		verLabel += fmt.Sprintf(" (-> %s)", a.latestRelease.TagName)
	}
	items = append(items, &mygo.MenuItem{
		Label: verLabel,
		Click: func(*mygo.MenuItem, *mygo.Window) {
			a.showMainWindow()
			if a.hasUpdate || a.localVersion == "" {
				a.triggerSeamlessUpdate()
			} else {
				a.triggerCheckUpdate(true)
			}
		},
	})
	items = append(items, mygo.Separator())

	if len(a.state.Services) == 0 {
		items = append(items, &mygo.MenuItem{
			Label:    cat.NoNodes(),
			Disabled: true,
		})
	} else {
		for _, svc := range a.state.Services {
			svcCopy := svc
			rt := a.mgr.StatusOf(svcCopy.ID)
			statusTag := rt.State.Label()
			checked := rt.State == runner.StateRunning || rt.State == runner.StateStarting
			label := fmt.Sprintf("%s  [%s · %s]", svcCopy.Name, statusTag, svcCopy.PrimaryListen())
			items = append(items, &mygo.MenuItem{
				Label:   label,
				Type:    mygo.MenuItemType("checkbox"),
				Checked: checked,
				Click: func(*mygo.MenuItem, *mygo.Window) {
					a.dispatchUI(func() {
						a.toggleService(svcCopy)
					})
				},
			})
		}
		items = append(items, mygo.Separator())
		items = append(items, &mygo.MenuItem{
			Label: cat.ActionStartAll(),
			Click: func(*mygo.MenuItem, *mygo.Window) {
				a.dispatchUI(func() {
					a.startAllServices()
				})
			},
		})
		items = append(items, &mygo.MenuItem{
			Label: cat.ActionStopAll(),
			Click: func(*mygo.MenuItem, *mygo.Window) {
				a.dispatchUI(func() {
					a.stopAllServices()
				})
			},
		})
	}

	items = append(items, mygo.Separator())
	items = append(items, &mygo.MenuItem{
		Label: cat.CheckClientUpdates() + "…",
		Click: func(*mygo.MenuItem, *mygo.Window) {
			checkForClientUpdates()
		},
	})
	items = append(items, &mygo.MenuItem{
		Label: cat.CheckUpdates(),
		Click: func(*mygo.MenuItem, *mygo.Window) {
			a.dispatchUI(func() {
				a.triggerCheckUpdate(true)
			})
		},
	})
	items = append(items, &mygo.MenuItem{
		Label: cat.MenuPreferences(),
		Click: func(*mygo.MenuItem, *mygo.Window) {
			a.showMainWindow()
			a.dispatchUI(func() {
				a.activeTab = TabSettings
			})
		},
	})
	items = append(items, mygo.Separator())
	items = append(items, &mygo.MenuItem{
		Label: cat.TrayQuit(),
		Click: func(*mygo.MenuItem, *mygo.Window) {
			a.quitting = true
			if a.mgr != nil {
				_ = a.mgr.StopAll()
			}
			mygo.App.Quit()
		},
	})

	return mygo.NewMenu(items)
}

func (a *app) showMainWindow() {
	if a.win == nil {
		return
	}
	if a.state.AppIcon == appIconMenubar && runtime.GOOS == "darwin" {
		mygo.App.SetActivationPolicy(mygo.ActivationPolicyRegular)
	}
	a.win.Show()
	a.win.Focus()
}
