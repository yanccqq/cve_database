package refresh

var (
	refreshIndexTableChan    = make(chan int)
	refreshIndexLoginBtnChan = make(chan int)
)

func SendRefreshIndexTableRequest() {
	refreshIndexTableChan <- 0
}

func GetRefreshIndexTableChan() chan int {
	return refreshIndexTableChan
}

func CloseRefreshIndexTableChan() {
	close(refreshIndexTableChan)
}

func SendRefreshIndexLoginBtnRequest(flag int) {
	refreshIndexLoginBtnChan <- flag
}

func GetRefreshIndexLoginBtnChan() chan int {
	return refreshIndexLoginBtnChan
}

func CloseRefreshIndexLoginBtnChan() {
	close(refreshIndexLoginBtnChan)
}


