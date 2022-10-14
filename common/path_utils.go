package common

import (
	"log"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strings"
)

// 获取项目所在绝对路径
func GetCurrentAbsolutePathPathByCaller() string {
	absolutePath := getCurrentAbPathByExecutable()
	if strings.Contains(absolutePath, getTmpDir()) {
		absolutePath = getCurrentAbPathByCaller()
	}
	log.Printf("项目的执行程序所在的绝对路径：%s\n", absolutePath)
	return absolutePath
}

// 获取系统临时目录(兼容go run)
func getTmpDir() string {
	dir := os.Getenv("TEMP")
	if dir == "" {
		dir = os.Getenv("TMP")
	}
	res, _ := filepath.EvalSymlinks(dir)
	return res
}

// 获取当前执行文件绝对路径(go build)
func getCurrentAbPathByExecutable() string {
	exePath, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	res, _ := filepath.EvalSymlinks(filepath.Dir(exePath))
	return res
}

// 获取当前执行文件绝对路径(go run)
func getCurrentAbPathByCaller() string {
	var absolutePath string
	_, filename, _, ok := runtime.Caller(0)
	if ok {
		absolutePath = path.Dir(filename)
	}
	var splitAbsolutePath string
	if strings.Contains(absolutePath, "/") {
		lastIndex := strings.LastIndex(absolutePath, "/")
		splitAbsolutePath = absolutePath[0:lastIndex]
	}
	return splitAbsolutePath
}
