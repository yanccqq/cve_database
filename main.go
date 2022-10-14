package main

import (
	"bytes"
	"log"
	"os"
	"os/exec"
	"runtime"
	"runtime/pprof"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/data/validation"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/yanccqq/cve_database/common"
	"github.com/yanccqq/cve_database/config"
	"github.com/yanccqq/cve_database/index"
	"github.com/yanccqq/cve_database/notification"
	"github.com/yanccqq/cve_database/refresh"
	"github.com/yanccqq/cve_database/service"
)

var (
	baseFilePath string
)

func init() {
	baseFilePath = common.GetCurrentAbsolutePathPathByCaller()
	os.Setenv("FYNE_FONT", baseFilePath+"/font/OPPOSans-M.ttf")
	common.WriteConfigToYML("spring.datasource.url", "jdbc:sqlite:"+baseFilePath+"/db/cve_database.db")
}

func main() {
	// 测试代码
	f, _ := os.OpenFile("cpu.pprof", os.O_CREATE|os.O_RDWR, 0644)
	defer f.Close()
	pprof.StartCPUProfile(f)
	defer pprof.StopCPUProfile()
	// 初始化数据库
	err := config.InitSqlite()
	if err != nil {
		log.Panicf("数据库初始化异常：%s\n", err.Error())
	}

	// 删除上一次的登录用户
	var userAPi service.UserApi
	userAPi.RemoveAll()

	// 加载首页
	myApp := app.NewWithID("RedHat漏洞数据库")
	iconResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/icon.png")
	myApp.SetIcon(iconResource)
	myApp.Settings().SetTheme(theme.LightTheme())
	myWindow := myApp.NewWindow("RedHat漏洞数据库")
	content, err := index.LoadIndex(myWindow)
	if err == nil {
		myWindow.SetContent(content)
	}
	myWindow.SetOnClosed(
		func() {
			refresh.CloseRefreshIndexTableChan()
			refresh.CloseRefreshIndexLoginBtnChan()
		},
	)
	myWindow.SetMainMenu(makeMenu(myApp, myWindow, content))
	myWindow.SetFixedSize(true)
	myWindow.SetMaster()
	myWindow.Resize(fyne.NewSize(1000, 600))
	myWindow.CenterOnScreen()

	systemctlType := runtime.GOOS
	if systemctlType == "linux" {
		// 判断是否存在实例（go run情况下没用）
		psCmd := exec.Command("ps", "-ef")
		psStdout, _ := setCommandStd(psCmd)
		err = psCmd.Run()
		if err != nil {
			log.Fatalf("执行ps命令失败，出现异常：%s\n", err.Error())
		}
		grepCmd := exec.Command("grep", "cve_database")
		grepCmd.Stdin = psStdout
		grepStdout, grepStderr := setCommandStd(grepCmd)
		err = grepCmd.Run()
		if err != nil {
			log.Printf("执行grep命令失败，出现异常：%s\n", grepStderr.String())
		}
		if grepStdout.Len() > 0 {
			// go run没用
			grepStdoutStr := grepStdout.String()
			log.Println(grepStdoutStr)
			count := strings.Count(grepStdoutStr, baseFilePath+"/cve_database")
			count2 := strings.Count(grepStdoutStr, "./cve_database")
			// 当前程序已经运行所以要大于1
			if count > 1 || count2 > 1 || (count+count2) > 1 {
				notification.InformationNotification("请勿重复打开")
				myWindow.Close()
			} else {
				myWindow.ShowAndRun()
			}
		} else {
			myWindow.ShowAndRun()
		}
	} else {
		myWindow.ShowAndRun()
	}
}

func makeMenu(a fyne.App, myWindow fyne.Window, dataContent fyne.CanvasObject) *fyne.MainMenu {
	generalSettingsItem := fyne.NewMenuItem("基本设置", func() {
		// 头部
		backBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/back.png")
		backBtn := widget.NewButtonWithIcon("返回", backBtnResource, func() {
			myWindow.SetContent(dataContent)
			myWindow.Content().Refresh()
		})
		btnHBox := container.NewHBox(backBtn)
		titleLable := widget.NewLabel("基本设置")
		headVBox := container.NewVBox(btnHBox, widget.NewSeparator(), titleLable)

		website := widget.NewEntry()
		website.SetPlaceHolder("https://192.168.160.235:8867/")
		website.Validator = validation.NewRegexp(`^((ht|f)tps?:\/\/)?[\w-]+(\.[\w-]+)+:\d{1,5}\/?$`, "网址不合法")
		websiteText := common.ReadWebsiteConfigNoCheck()
		if len(websiteText) > 0 {
			website.SetText(websiteText)
		}
		databasePath := widget.NewEntry()
		absolutePath := common.GetCurrentAbsolutePathPathByCaller()
		databasePath.SetText(absolutePath + "/db/cve_database.db")
		databasePath.Disable()
		form := &widget.Form{
			Items: []*widget.FormItem{
				{Text: "网址", Widget: website, HintText: "漏洞管理平台部署后的网址"},
				{Text: "路径", Widget: databasePath, HintText: "数据库所在文件夹的绝对路径"},
			},
			OnCancel: func() {
				log.Println("取消设置")
			},
			OnSubmit: func() {
				common.WriteConfigToYML("config.website", website.Text)
				common.WriteConfigToYML("spring.datasource.url", "jdbc:sqlite:"+baseFilePath+"/db/cve_database.db")
				notification.InformationNotification("保存成功")
			},
		}
		form.SubmitText = "提交"
		form.CancelText = "取消"
		content := container.NewBorder(headVBox, nil, nil, nil, form)
		myWindow.SetContent(content)
	})
	quitSettingsItem := fyne.NewMenuItem("退出", nil)
	quitSettingsItem.IsQuit = true
	settingsMenu := fyne.NewMenu("设置", generalSettingsItem, quitSettingsItem)
	main := fyne.NewMainMenu(
		settingsMenu,
	)
	return main
}

func setCommandStd(cmd *exec.Cmd) (stdout, stderr *bytes.Buffer) {
	stdout = &bytes.Buffer{}
	stderr = &bytes.Buffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return
}
