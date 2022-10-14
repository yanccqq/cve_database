package index

import (
	"fmt"
	"image/color"
	"log"
	"os/exec"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
	xwidget "fyne.io/x/fyne/widget"
	"github.com/yanccqq/cve_database/common"
	"github.com/yanccqq/cve_database/custom"
	"github.com/yanccqq/cve_database/models/information"
	"github.com/yanccqq/cve_database/notification"
	refreshData "github.com/yanccqq/cve_database/refresh"
	"github.com/yanccqq/cve_database/service"
	"github.com/yanccqq/cve_database/utils"
)

var (
	myWindow     fyne.Window
	loginBtn     *widget.Button
	content      *fyne.Container
	headerVBox   *fyne.Container
	baseFilePath string
)

func init() {
	baseFilePath = common.GetCurrentAbsolutePathPathByCaller()
}

// 加载首页
func LoadIndex(win fyne.Window) (fyne.CanvasObject, error) {
	myWindow = win
	// 按钮组
	refreshBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/refresh.png")
	refreshBtn := widget.NewButtonWithIcon("刷新", refreshBtnResource, func() {})
	loginBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/login.png")
	loginBtn = widget.NewButtonWithIcon("登录", loginBtnResource, func() {})
	loginBtn.OnTapped = utils.LoginTapped(myWindow, loginBtn, true)
	btnHBox := container.NewHBox(refreshBtn, loginBtn)

	// CVE漏洞列表
	var informationsApi service.InformationApi
	informations, err := informationsApi.ListAll()
	if err != nil {
		errorMsg := fmt.Sprintf("获取全部漏洞信息出现异常: %s", err.Error())
		log.Println(errorMsg)
		notification.ErrorNotification(errorMsg, myWindow)
		return nil, err
	}

	cveTable := loadCveTable(informations)

	titleLable := widget.NewLabel("CVE漏洞列表")
	headerVBox = container.NewVBox(titleLable, widget.NewSeparator(), btnHBox)
	content = container.NewBorder(headerVBox, nil, nil, nil, cveTable)
	refreshBtn.OnTapped = refresh()
	go RefreshLoginButton()
	go RefreshCveTableData()
	return content, nil
}

func loadCveTable(informations []information.Information) *widget.Table {
	cveTable := widget.NewTable(
		func() (int, int) {
			return len(informations) + 1, 5
		},
		func() fyne.CanvasObject {
			return container.NewMax(widget.NewLabel("cell content"))
		},
		func(id widget.TableCellID, cell fyne.CanvasObject) {
			cellContainer := cell.(*fyne.Container)
			cellContainer.RemoveAll()
			if id.Row == 0 {
				switch id.Col {
				case 0:
					cellContainer.Add(widget.NewLabel("编号"))
				case 1:
					cellContainer.Add(widget.NewLabel("CVE编号"))
				case 2:
					cellContainer.Add(widget.NewLabel("漏洞详情"))
				case 3:
					cellContainer.Add(widget.NewLabel("CVSS评分"))
				case 4:
					cellContainer.Add(widget.NewLabel("发布日期"))
				}
			} else {
				switch id.Col {
				case 0:
					cellContainer.Add(widget.NewLabel(fmt.Sprintf("%d", id.Row)))
				case 1:
					customLabel := custom.NewCustomLabel(" "+informations[id.Row-1].LoopholeCve, color.NRGBA{R: 33, G: 150, B: 243, A: 255})
					cellContainer.Add(customLabel)
				case 2:
					label := widget.NewLabel(informations[id.Row-1].LoopholeInformation)
					label.Wrapping = fyne.TextTruncate
					label.Refresh()
					cellContainer.Add(label)
				case 3:
					cellContainer.Add(widget.NewLabel(informations[id.Row-1].LoopholeCvss))
				case 4:
					cellContainer.Add(widget.NewLabel(informations[id.Row-1].UpdateTime))
				}
			}
		})
	cveTable.SetColumnWidth(0, 60)
	cveTable.SetColumnWidth(1, 150)
	cveTable.SetColumnWidth(2, 550)
	cveTable.SetColumnWidth(3, 100)
	cveTable.SetColumnWidth(4, 120)

	return cveTable
}

func refresh() func() {
	return func() {
		notification.InformationNotification("正在刷新漏洞数据，请稍后")
		loadingGif, _ := xwidget.NewAnimatedGif(storage.NewFileURI(baseFilePath + "/img/loading.gif"))
		loadingGif.SetMinSize(fyne.NewSize(40, 40))
		loadingGif.Start()
		loadingContent := container.NewCenter(container.NewVBox(
			loadingGif,
			widget.NewLabel("loading..."),
			widget.NewLabel(""),
		))
		content.RemoveAll()
		content.Add(headerVBox)
		content.Add(nil)
		content.Add(nil)
		content.Add(loadingContent)
		content.Refresh()
		cmd := exec.Command(baseFilePath+"/jdk/bin/java", "-jar", baseFilePath+"/jar/get_data-2.0.jar")
		err := cmd.Run()
		if err != nil {
			errorImgResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/error.png")
			errorImg := canvas.NewImageFromResource(errorImgResource)
			errorImg.FillMode = canvas.ImageFillContain
			errorImg.SetMinSize(fyne.NewSize(40, 40))
			errorContent := container.NewCenter(container.NewVBox(
				errorImg,
				widget.NewLabel("刷新数据失败"),
				widget.NewLabel(""),
			))
			content.Remove(loadingContent)
			content.Add(errorContent)
			content.Refresh()
			notification.ErrorNotification("刷新漏洞数据失败", myWindow)
		} else {
			var informationsApi service.InformationApi
			informations, err := informationsApi.ListAll()
			if err != nil {
				errorMsg := fmt.Sprintf("获取全部漏洞信息出现异常: %s", err.Error())
				log.Println(errorMsg)
				notification.ErrorNotification(errorMsg, myWindow)
			} else {
				cveTable := loadCveTable(informations)
				content.Remove(loadingContent)
				content.Add(cveTable)
				content.Refresh()
			}

			notification.InformationNotification("刷新漏洞数据成功")
		}
	}
}

func RefreshLoginButton() {
	refreshIndexLoginBtnChan := refreshData.GetRefreshIndexLoginBtnChan()
	for success := range refreshIndexLoginBtnChan { // 通道关闭后会退出for range循环
		log.Printf("刷新表格数据通道接收到的数据：%d\n", success)
		if success == 0 {
			loginBtn.SetText("退出登录")
			quitBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/quit.png")
			loginBtn.SetIcon(quitBtnResource)
			loginBtn.OnTapped = func() {
				var userApi *service.UserApi
				err := userApi.RemoveAll()
				if err != nil {
					notification.ErrorNotification(err.Error(), myWindow)
				} else {
					loginBtn.SetText("登录")
					loginBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/login.png")
					loginBtn.SetIcon(loginBtnResource)
					loginBtn.OnTapped = utils.LoginTapped(myWindow, loginBtn, true)
					loginBtn.Refresh()
					notification.InformationNotification("退出登录成功")
				}
			}
		} else {
			loginBtn.SetText("登录")
			loginBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/login.png")
			loginBtn.SetIcon(loginBtnResource)
			loginBtn.OnTapped = utils.LoginTapped(myWindow, loginBtn, true)
		}
		loginBtn.Refresh()
	}
}

func RefreshCveTableData() {
	refreshIndexTableChan := refreshData.GetRefreshIndexTableChan()
	for success := range refreshIndexTableChan { // 通道关闭后会退出for range循环
		log.Printf("刷新表格数据通道接收到的数据：%d\n", success)
		loadingGif, _ := xwidget.NewAnimatedGif(storage.NewFileURI(baseFilePath + "/img/loading.gif"))
		loadingGif.SetMinSize(fyne.NewSize(40, 40))
		loadingGif.Start()
		loadingContent := container.NewCenter(container.NewVBox(
			loadingGif,
			widget.NewLabel("loading..."),
			widget.NewLabel(""),
		))
		content.RemoveAll()
		content.Add(headerVBox)
		content.Add(nil)
		content.Add(nil)
		content.Add(loadingContent)
		content.Refresh()
		var informationsApi service.InformationApi
		informations, err := informationsApi.ListAll()
		if err != nil {
			errorMsg := fmt.Sprintf("导入后刷新漏洞信息出现异常: %s", err.Error())
			log.Println(errorMsg)
			notification.ErrorNotification(errorMsg, myWindow)
		} else {
			cveTable := loadCveTable(informations)
			content.Remove(loadingContent)
			content.Add(cveTable)
			content.Refresh()
		}
	}
}
