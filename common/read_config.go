package common

import (
	"log"
	"net"
	"regexp"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"github.com/spf13/viper"
	"github.com/yanccqq/cve_database/notification"
)

func ReadWebsiteConfig(myWindow fyne.Window) string {
	absolutePath := GetCurrentAbsolutePathPathByCaller()
	viper.AddConfigPath(absolutePath + "/config")
	viper.SetConfigType("yml")
	viper.SetConfigName("application")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("读取配置文件失败，出现异常：%s\n", err.Error())
	}
	website := viper.Get("config.website").(string)
	if len(website) <= 0 {
		notification.ErrorNotification("请先配置漏洞管理平台部署后网址", myWindow)
		return ""
	}
	websiteMatched, err := regexp.MatchString("^((ht|f)tps?:\\/\\/)?[\\w-]+(\\.[\\w-]+)+:\\d{1,5}\\/?$", website)
	if err != nil {
		log.Fatalf("校验漏洞管理平台部署后网址失败，出现异常：%s\n", err.Error())
	}
	websiteMatched2, err := regexp.MatchString("^(((ht|f)tps?):\\/\\/)?([^!@#$%^&*?.\\s-]([^!@#$%^&*?.\\s]{0,63}[^!@#$%^&*?.\\s])?\\.)+[a-z]{2,6}\\/?", website)
	if err != nil {
		log.Fatalf("校验漏洞管理平台部署后网址失败，出现异常：%s\n", err.Error())
	}
	if websiteMatched || websiteMatched2 {
		if serverPing(website) {
			if strings.HasSuffix(website, "/") {
				return website
			} else {
				return website + "/"
			}
		} else {
			notification.ErrorNotification("漏洞管理平台部署后网址没有响应", myWindow)
			return ""
		}
	} else {
		notification.ErrorNotification("配置漏洞管理平台部署后网址格式错误", myWindow)
		return ""
	}
}

func ReadWebsiteConfigNoCheck() string {
	absolutePath := GetCurrentAbsolutePathPathByCaller()
	viper.AddConfigPath(absolutePath + "/config")
	viper.SetConfigType("yml")
	viper.SetConfigName("application")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("读取配置文件失败，出现异常：%s\n", err.Error())
	}
	website := viper.Get("config.website").(string)
	return website
}

func serverPing(target string) bool {
	ipReg, err := regexp.Compile("((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})(\\.((2(5[0-5]|[0-4]\\d))|[0-1]?\\d{1,2})){3}")
	if err != nil {
		log.Printf("IP正则表达式初始化失败，出现异常：%s\n", err.Error())
	}
	ip := ipReg.Find([]byte(target))
	ipStr := string(ip)
	var portStr string
	if strings.Contains(target, ":") {
		lastIndex := strings.LastIndex(target, ":")
		portStr = target[lastIndex:]
		if strings.HasSuffix(portStr, "/") {
			portStr = portStr[0 : len(portStr)-1]
		}
	}
	if len(ipStr) > 0 {
		timeout := time.Duration(5 * time.Second)
		_, err := net.DialTimeout("tcp", ipStr+portStr, timeout)
		if err != nil {
			log.Printf("漏洞管理平台没有响应，出现异常：%s\n", err.Error())
			return false
		}
		return true
	}
	return false
}
