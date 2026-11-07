package main

import (
	"log"
	"os"

	"naive-client/internal/app"
	"naive-client/internal/tunhelper"
)

func main() {
	if tunhelper.IsHelper(os.Args) {
		if err := tunhelper.RunHelper(os.Args); err != nil {
			log.Fatal(err)
		}
		return
	}

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
