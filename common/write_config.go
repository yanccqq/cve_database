package common

import (
	"log"

	"github.com/spf13/viper"
)

func WriteConfigToYML(configKey, configValue string) {
	absolutePath := GetCurrentAbsolutePathPathByCaller()
	viper.AddConfigPath(absolutePath + "/config")
	viper.SetConfigType("yml")
	viper.SetConfigName("application")
	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("读取配置文件失败，出现异常：%s\n", err.Error())
	}
	viper.Set(configKey, configValue)
	viper.WriteConfig()
}
