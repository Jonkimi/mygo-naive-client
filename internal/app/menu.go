package app

import (
	"runtime"

	"github.com/egoist/mygo"
)

func (a *app) installAppMenu() {
	if a.headless {
		return
	}
	var top []*mygo.MenuItem

	cat := a.catalog()
	if runtime.GOOS == "darwin" {
		top = append(top, &mygo.MenuItem{
			Label: "NaiveClient",
			Submenu: []*mygo.MenuItem{
				{Role: mygo.MenuRole("about"), Label: cat.MenuAbout},
				{
					Label: cat.CheckClientUpdates + "…",
					Click: func(*mygo.MenuItem, *mygo.Window) {
						checkForClientUpdates()
					},
				},
				mygo.Separator(),
				{
					Label:       cat.MenuPreferences,
					Accelerator: "CmdOrCtrl+,",
					Click: func(*mygo.MenuItem, *mygo.Window) {
						a.showMainWindow()
						a.dispatchUI(func() {
							a.activeTab = TabSettings
						})
					},
				},
				mygo.Separator(),
				{Role: mygo.MenuRole("hide"), Label: cat.TrayHide},
				{Role: mygo.MenuRole("hideOthers")},
				{Role: mygo.MenuRole("unhide")},
				mygo.Separator(),
				{
					Label:       cat.TrayQuit,
					Accelerator: "CmdOrCtrl+Q",
					Click: func(*mygo.MenuItem, *mygo.Window) {
						a.quitting = true
						if a.mgr != nil {
							_ = a.mgr.StopAll()
						}
						mygo.App.Quit()
					},
				},
			},
		})
	}

	top = append(top, &mygo.MenuItem{
		Label: cat.NavNodes,
		Submenu: []*mygo.MenuItem{
			{
				Label:       cat.NewService + "...",
				Accelerator: "CmdOrCtrl+N",
				Click: func(*mygo.MenuItem, *mygo.Window) {
					a.showMainWindow()
					a.dispatchUI(func() {
						a.openCreateServiceDialog()
					})
				},
			},
			{
				Label:       cat.ImportClipboard + "...",
				Accelerator: "CmdOrCtrl+Shift+V",
				Click: func(*mygo.MenuItem, *mygo.Window) {
					a.showMainWindow()
					a.dispatchUI(func() {
						a.openImportDialog()
					})
				},
			},
			mygo.Separator(),
			{
				Label: cat.CheckClientUpdates + "…",
				Click: func(*mygo.MenuItem, *mygo.Window) {
					checkForClientUpdates()
				},
			},
			{
				Label:       cat.CheckUpdates,
				Accelerator: "CmdOrCtrl+R",
				Click: func(*mygo.MenuItem, *mygo.Window) {
					a.showMainWindow()
					a.dispatchUI(func() {
						a.triggerCheckUpdate(true)
					})
				},
			},
		},
	})

	top = append(top, &mygo.MenuItem{
		Label: cat.MenuEdit,
		Submenu: []*mygo.MenuItem{
			{Role: mygo.RoleUndo},
			{Role: mygo.MenuRole("redo")},
			mygo.Separator(),
			{Role: mygo.MenuRole("cut")},
			{Role: mygo.MenuRole("copy")},
			{Role: mygo.MenuRole("paste")},
			{Role: mygo.MenuRole("selectAll")},
		},
	})

	top = append(top, &mygo.MenuItem{
		Label: cat.MenuWindow,
		Submenu: []*mygo.MenuItem{
			{Role: mygo.MenuRole("minimize")},
			{Role: mygo.MenuRole("zoom")},
			{Role: mygo.MenuRole("close")},
		},
	})

	mygo.App.SetMenu(mygo.NewMenu(top))
}
