// Команда darkprince — VPN-клиент DarkPrince для Linux.
//
// Один бинарник: и служба (darkprince daemon), и управление ею. Служба
// держит ядро Xray и туннель, остальные команды — тонкий клиент поверх
// unix-сокета.
package main

import (
	"fmt"
	"os"

	"github.com/darkprince922/darkprincevpnlinux/internal/cli"
)

func main() {
	if err := cli.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "Ошибка:", err)
		os.Exit(1)
	}
}
