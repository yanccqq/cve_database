package details

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
	"github.com/yanccqq/cve_database/common"
	"github.com/yanccqq/cve_database/models/user"
	"github.com/yanccqq/cve_database/notification"
	"github.com/yanccqq/cve_database/refresh"
	"github.com/yanccqq/cve_database/service"
	"github.com/yanccqq/cve_database/utils"
)

var (
	baseFilePath string
)

func init() {
	baseFilePath = common.GetCurrentAbsolutePathPathByCaller()
}

func LoadDetails(cve string) {
	if len(cve) > 0 {
		trimSpaceCve := strings.TrimSpace(cve)
		isCVE, err := regexp.Match("^(?i)$|^CVE-\\d{4}-\\d{1,}$", []byte(trimSpaceCve))
		if err != nil {
			log.Panicln(err.Error())
		}

		if isCVE {
			cveDetailsWindow := fyne.CurrentApp().NewWindow(trimSpaceCve + "漏洞详情")
			importBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/import.png")
			var informationsApi service.InformationApi
			information, err := informationsApi.GetInformationByCVE(trimSpaceCve)
			if err != nil {
				errorMsg := fmt.Sprintf("获取CVE漏洞详情出现异常: %s", err.Error())
				log.Println(errorMsg)
				notification.ErrorNotification(errorMsg, cveDetailsWindow)
			}

			platformGroup := widget.NewCheckGroup([]string{"服务器", "桌面"}, func(s []string) { log.Println("导入漏洞时选中了：", s) })
			platformGroup.Horizontal = true
			selectedPlatform := []string{"服务器"}
			platformGroup.SetSelected(selectedPlatform)
			importBtn := widget.NewButtonWithIcon("导入", importBtnResource, func() {
				website := common.ReadWebsiteConfig(cveDetailsWindow)
				if len(website) > 0 {
					var userApi *service.UserApi
					loginUser, err := userApi.Get()
					if err != nil {
						log.Printf("获取登录用户信息失败，出现异常：%s\n", err.Error())
						notification.ErrorNotification("获取登录用户失败或者没有登录", cveDetailsWindow)
					} else {
						if loginUser == (user.User{}) {
							notification.ErrorNotification("请先登录", cveDetailsWindow)
						} else {
							cveRaw := make(map[string]interface{})
							cveRawTypeStrList := platformGroup.Selected
							if len(cveRawTypeStrList) > 0 {
								var cveRawTypeList []int
								for _, cveRawTypeStr := range cveRawTypeStrList {
									if cveRawTypeStr == "服务器" {
										cveRawTypeList = append(cveRawTypeList, 0)
									}
									if cveRawTypeStr == "桌面" {
										cveRawTypeList = append(cveRawTypeList, 1)
									}
								}
								cveRaw["cveRawTypeList"] = cveRawTypeList
								cveRaw["cve"] = information.LoopholeCve
								cveRaw["cveRawDate"] = information.UpdateTime
								cveRaw["cvss3"] = information.LoopholeCvss
								cveRaw["details"] = information.LoopholeInformation
								var fixStates string
								for _, platformAndPackages := range information.PlatformAndPackages {
									platform := strings.Replace(platformAndPackages.Platform, " ", "", -1)
									platform = strings.ToLower(platform)
									if strings.Contains(platform, "linux7") || strings.Contains(platform, "linux8") {
										fixStates = fixStates + platformAndPackages.Platform + " [" + platformAndPackages.SoftwarePackage + "];\n"
									}
								}
								if len(fixStates) > 0 {
									lastIndex := strings.LastIndex(fixStates, "\n")
									fixStates = fixStates[0:lastIndex]
									cveRaw["fixStates"] = fixStates
								}
								cveRawBytesData, _ := json.Marshal(cveRaw)
								// 开始登录
								payload := strings.NewReader(string(cveRawBytesData))
								req, err := http.NewRequest("POST", website+"cveRaw/clientImportCveRaw", payload)
								if err != nil {
									log.Fatalf("初始化导入请求失败，出现异常：%s\n", err.Error())
								}
								req.Header.Add("Content-Type", "application/json;charset=UTF8")
								req.Header.Add("Authorization", loginUser.Token)

								// 跳过证书验证
								tr := &http.Transport{
									TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
								}
								client := &http.Client{Timeout: 30 * time.Second, Transport: tr}
								res, err := client.Do(req)
								if err != nil {
									log.Printf("导入失败，出现异常：%s\n", err.Error())
								}
								log.Println(res.StatusCode)
								if res.StatusCode == 200 {
									var informationApi service.InformationApi
									err := informationApi.UpdateInformationByCVE(trimSpaceCve)
									if err != nil {
										log.Printf("更新数据库出现异常：%s\n", err.Error())
										notification.ErrorNotification("导入漏洞信息失败", cveDetailsWindow)
									} else {
										refresh.SendRefreshIndexTableRequest()
										notification.InformationNotification("导入漏洞信息成功")
									}
								} else if res.StatusCode == 401 || res.StatusCode == 403 {
									notification.ErrorNotification("登录失效或权限不足，请重新登录", cveDetailsWindow)
								} else {
									content, err := ioutil.ReadAll(res.Body)
									if err != nil {
										log.Printf("读取返回数据失败，出现异常：%s\n", err.Error())
									}
									responseContent := make(map[string]interface{})
									err = json.Unmarshal(content, &responseContent)
									if err != nil {
										log.Printf("将返回数据转换成对象失败，出现异常：%s\n", err.Error())
									}
									if _, ok := responseContent["msg"]; ok {
										if !isNil(responseContent["msg"]) {
											notification.ErrorNotification(responseContent["msg"].(string), cveDetailsWindow)
										} else {
											notification.ErrorNotification("内部异常", cveDetailsWindow)
										}
									} else {
										notification.ErrorNotification("内部异常", cveDetailsWindow)
									}
									defer res.Body.Close()
								}
							} else {
								notification.ErrorNotification("请选择导入的系统类型", cveDetailsWindow)
							}
						}
					}
				}
			})
			var userApi service.UserApi
			u, _ := userApi.Get()
			var btnHBox *fyne.Container
			if u == (user.User{}) {
				loginBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/login.png")
				loginBtn := widget.NewButtonWithIcon("登录", loginBtnResource, func() {})
				loginBtn.OnTapped = utils.LoginTapped(cveDetailsWindow, loginBtn, false)
				btnHBox = container.NewHBox(platformGroup, importBtn, loginBtn)
			} else {
				btnHBox = container.NewHBox(platformGroup, importBtn)
			}

			cveNumberLabel := widget.NewLabel("CVE编号：")
			cveValue := widget.NewLabel(information.LoopholeCve)
			loopholeCvssLabel := widget.NewLabel("CVSS评分：")
			loopholeCvssValue := widget.NewLabel(information.LoopholeCvss)
			updateTimeLabel := widget.NewLabel("更新时间：")
			updateTimeValue := widget.NewLabel(information.UpdateTime)
			cveFormLayout := container.New(layout.NewFormLayout(), cveNumberLabel, cveValue)
			loopholeCvssFormLayout := container.New(layout.NewFormLayout(), loopholeCvssLabel, loopholeCvssValue)
			updateTimeFormLayout := container.New(layout.NewFormLayout(), updateTimeLabel, updateTimeValue)
			informationContainer := container.NewGridWithColumns(3, cveFormLayout, loopholeCvssFormLayout, updateTimeFormLayout)

			descriptionLabel := widget.NewLabel("漏洞描述：")
			descriptionValue := widget.NewLabel(information.LoopholeInformation)
			descriptionValue.Wrapping = fyne.TextWrapBreak
			descriptionFormLayout := container.New(layout.NewFormLayout(), descriptionLabel, descriptionValue)
			detailsContainer := container.NewBorder(informationContainer, nil, nil, nil, descriptionFormLayout)

			cvedetailsTable := widget.NewTable(
				func() (int, int) { return len(information.PlatformAndPackages) + 1, 3 },
				func() fyne.CanvasObject {
					return widget.NewLabel("2022-12-31")
				},
				func(id widget.TableCellID, cell fyne.CanvasObject) {
					label := cell.(*widget.Label)

					if id.Row == 0 {
						switch id.Col {
						case 0:
							label.SetText("编号")
						case 1:
							label.SetText("受影响平台")
						case 2:
							label.SetText("受影响软件包")
						}
					} else {
						switch id.Col {
						case 0:
							label.SetText(fmt.Sprintf("%d", id.Row))
						case 1:
							label.Wrapping = fyne.TextWrapBreak
							label.SetText(information.PlatformAndPackages[id.Row-1].Platform)
						case 2:
							label.Wrapping = fyne.TextWrapBreak
							label.SetText(information.PlatformAndPackages[id.Row-1].SoftwarePackage)
						}
					}
				})
			cvedetailsTable.SetColumnWidth(0, 60)
			platformAndPackages := information.PlatformAndPackages
			maxPlatformColumnWidth := 0
			maxPackageColumnWidth := 0
			for _, platformAndPackage := range platformAndPackages {
				if len(platformAndPackage.Platform) > maxPlatformColumnWidth {
					maxPlatformColumnWidth = len(platformAndPackage.Platform)
				}
				if len(platformAndPackage.SoftwarePackage) > maxPackageColumnWidth {
					maxPackageColumnWidth = len(platformAndPackage.SoftwarePackage)
				}
			}
			cvedetailsTable.SetColumnWidth(1, float32(maxPlatformColumnWidth)*15)
			cvedetailsTable.SetColumnWidth(2, float32(maxPackageColumnWidth)*15)

			content := container.NewBorder(
				container.NewVBox(btnHBox, widget.NewSeparator()), nil, nil, nil, container.NewBorder(container.NewVBox(detailsContainer, widget.NewSeparator(), widget.NewLabel("受影响平台和对应软件包")), nil, nil, nil, cvedetailsTable))
			cveDetailsWindow.SetContent(content)

			cveDetailsWindow.SetFixedSize(true)
			cveDetailsWindow.Resize(fyne.NewSize(1000, 600))
			cveDetailsWindow.CenterOnScreen()
			cveDetailsWindow.Show()
		}
	}
}

func isNil(i interface{}) bool {
	vi := reflect.ValueOf(i)
	if vi.Kind() == reflect.Ptr {
		return vi.IsNil()
	}
	return false
}
