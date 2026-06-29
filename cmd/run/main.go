package main

import (
	"context"
	"log"
	"os"
	"os/signal"

	"github.com/POSIdev-community/aictl/internal/application"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill)
	defer stop()

	app, err := application.NewApplication()
	if err != nil {
		log.Fatal(err)
	}

	app.Run(ctx)
}
