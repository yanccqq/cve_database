package notification

import (
	"errors"
	"fmt"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
)

func InformationNotification(content string) {
	timeUnix := time.Now().Unix()
	formatTimeStr := time.Unix(timeUnix, 0).Format("2006-01-02 15:04:05")
	notificationTitle := fmt.Sprintf("提示信息 %s\n", formatTimeStr)
	fyne.CurrentApp().SendNotification(&fyne.Notification{
		Title:   notificationTitle,
		Content: content,
	})
}

func ErrorNotification(content string, win fyne.Window) {
	err := errors.New(content)
	dialog.ShowError(err, win)
}
