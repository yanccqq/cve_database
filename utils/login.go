package utils

import (
	"crypto/tls"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/data/validation"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/google/uuid"
	"github.com/yanccqq/cve_database/common"
	"github.com/yanccqq/cve_database/models/user"
	"github.com/yanccqq/cve_database/notification"
	"github.com/yanccqq/cve_database/refresh"
	"github.com/yanccqq/cve_database/service"
)

var (
	baseFilePath string
)

func init() {
	baseFilePath = common.GetCurrentAbsolutePathPathByCaller()
}

func LoginTapped(myWindow fyne.Window, btn *widget.Button, isIndex bool) func() {
	return func() {
		var userApi *service.UserApi
		u, _ := userApi.Get()
		if u == (user.User{}) {
			username := widget.NewEntry()
			username.Validator = validation.NewRegexp("^.+$", "用户名不能为空")
			username.SetPlaceHolder("漏洞管理平台用户名")
			password := widget.NewPasswordEntry()
			password.Validator = validation.NewRegexp("^.+$", "密码不能为空")
			password.SetPlaceHolder("漏洞管理平台密码")
			items := []*widget.FormItem{
				{Text: "用户名", Widget: username, HintText: "漏洞管理平台用户名"},
				{Text: "密码", Widget: password, HintText: "漏洞管理平台密码"},
			}

			loginForm := dialog.NewForm("登录漏洞管理平台", "确认", "取消", items, func(b bool) {
				if !b {
					return
				}
				website := common.ReadWebsiteConfig(myWindow)
				if len(website) > 0 {
					loginUser := make(map[string]string)
					loginUser["userName"] = username.Text
					loginUser["password"] = password.Text
					userBytesData, _ := json.Marshal(loginUser)
					// 开始登录
					payload := strings.NewReader(string(userBytesData))
					req, err := http.NewRequest("POST", website+"login", payload)
					if err != nil {
						log.Fatalf("初始化登录请求失败，出现异常：%s\n", err.Error())
					}
					req.Header.Add("Content-Type", "application/json;charset=UTF8")
					// 跳过证书验证
					tr := &http.Transport{
						TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
					}
					client := &http.Client{Timeout: 30 * time.Second, Transport: tr}
					res, err := client.Do(req)
					if err != nil {
						log.Printf("登录失败，出现异常：%s\n", err.Error())
					}
					log.Println(strings.Compare(res.Status, "200"))
					if res.StatusCode == 200 {
						uuidWithHyphen := uuid.New()
						uuid := strings.Replace(uuidWithHyphen.String(), "-", "", -1)
						user := user.User{}
						user.Id = uuid
						user.Token = res.Header.Get("Authorization")

						err = userApi.Add(&user)
						if err != nil {
							notification.ErrorNotification(err.Error(), myWindow)
						} else {
							btn.SetText("退出登录")
							quitBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/quit.png")
							btn.SetIcon(quitBtnResource)
							btn.OnTapped = func() {
								err = userApi.RemoveAll()
								if err != nil {
									notification.ErrorNotification(err.Error(), myWindow)
								} else {
									btn.SetText("登录")
									loginBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/login.png")
									btn.SetIcon(loginBtnResource)
									btn.OnTapped = LoginTapped(myWindow, btn, isIndex)
									if !isIndex {
										refresh.SendRefreshIndexLoginBtnRequest(1)
									}
									btn.Refresh()
									notification.InformationNotification("退出登录成功")
								}
							}
							if !isIndex {
								refresh.SendRefreshIndexLoginBtnRequest(0)
							}
							btn.Refresh()
							notification.InformationNotification("登录成功")
						}
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
								notification.ErrorNotification(responseContent["msg"].(string), myWindow)
							} else {
								notification.ErrorNotification("内部异常", myWindow)
							}
						} else {
							notification.ErrorNotification("内部异常", myWindow)
						}
						defer res.Body.Close()
					}
				}
			}, myWindow)
			loginForm.Resize(fyne.NewSize(300, 200))
			loginForm.Show()
		} else {
			btn.SetText("退出登录")
			quitBtnResource, _ := fyne.LoadResourceFromPath(baseFilePath + "/img/quit.png")
			btn.SetIcon(quitBtnResource)
			btn.OnTapped = func() {
				err := userApi.RemoveAll()
				if err != nil {
					notification.ErrorNotification(err.Error(), myWindow)
				} else {
					btn.SetText("登录")
					btn.OnTapped = LoginTapped(myWindow, btn, isIndex)
					btn.Refresh()
					notification.InformationNotification("退出登录成功")
				}
			}
			btn.Refresh()
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
