package main

import "github.com/spf13/viper"

func main() {
	cfg := viper.New()
	cfg.SetConfigName("credmanager")
	cfg.AddConfigPath(".")

}
