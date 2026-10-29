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

	if runtime.GOOS == "darwin" {
		top = append(top, &mygo.MenuItem{
			Label: "NaiveClient",
			Submenu: []*mygo.MenuItem{
				{Role: mygo.MenuRole("about"), Label: "关于 NaiveClient"},
				{
					Label: "检查 NaiveClient 更新…",
					Click: func(*mygo.MenuItem, *mygo.Window) {
						checkForClientUpdates()
					},
				},
				mygo.Separator(),
				{
					Label:       "偏好设置...",
					Accelerator: "CmdOrCtrl+,",
					Click: func(*mygo.MenuItem, *mygo.Window) {
						a.showMainWindow()
						a.dispatchUI(func() {
							a.openSettingsDialog()
						})
					},
				},
				mygo.Separator(),
				{Role: mygo.MenuRole("hide"), Label: "隐藏 NaiveClient"},
				{Role: mygo.MenuRole("hideOthers"), Label: "隐藏其他"},
				{Role: mygo.MenuRole("unhide"), Label: "全部显示"},
				mygo.Separator(),
				{
					Label:       "退出 NaiveClient",
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
		Label: "服务",
		Submenu: []*mygo.MenuItem{
			{
				Label:       "新建服务...",
				Accelerator: "CmdOrCtrl+N",
				Click: func(*mygo.MenuItem, *mygo.Window) {
					a.showMainWindow()
					a.dispatchUI(func() {
						a.openCreateServiceDialog()
					})
				},
			},
			{
				Label:       "从剪贴板导入...",
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
				Label: "检查客户端更新…",
				Click: func(*mygo.MenuItem, *mygo.Window) {
					checkForClientUpdates()
				},
			},
			{
				Label:       "检查 NaiveProxy 核心更新",
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
		Label: "编辑",
		Submenu: []*mygo.MenuItem{
			{Role: mygo.RoleUndo, Label: "撤销"},
			{Role: mygo.MenuRole("redo"), Label: "重做"},
			mygo.Separator(),
			{Role: mygo.MenuRole("cut"), Label: "剪切"},
			{Role: mygo.MenuRole("copy"), Label: "复制"},
			{Role: mygo.MenuRole("paste"), Label: "粘贴"},
			{Role: mygo.MenuRole("selectAll"), Label: "全选"},
		},
	})

	top = append(top, &mygo.MenuItem{
		Label: "窗口",
		Submenu: []*mygo.MenuItem{
			{Role: mygo.MenuRole("minimize"), Label: "最小化"},
			{Role: mygo.MenuRole("zoom"), Label: "缩放"},
			{Role: mygo.MenuRole("close"), Label: "关闭窗口"},
		},
	})

	mygo.App.SetMenu(mygo.NewMenu(top))
}
