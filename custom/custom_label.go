package custom

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/widget"
	"github.com/yanccqq/cve_database/details"
)

var _ fyne.CanvasObject = (*CustomLabel)(nil)

type CustomLabel struct {
	*canvas.Text
}

func (customLabel *CustomLabel) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(canvas.NewText(customLabel.Text.Text, customLabel.Color))
}

func NewCustomLabel(text string, color color.Color) *CustomLabel {
	customLabel := &CustomLabel{}
	customLabel.Text = canvas.NewText(text, color)
	customLabel.Alignment = fyne.TextAlignLeading
	customLabel.Text.Refresh()
	return customLabel
}

func (customLabel *CustomLabel) Tapped(_ *fyne.PointEvent) {
	details.LoadDetails(customLabel.Text.Text)
}

func (customLabel *CustomLabel) TappedSecondary(*fyne.PointEvent) {
}
