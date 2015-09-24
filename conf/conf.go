package conf

import (
	"code.google.com/p/gcfg"
	"flag"
	"fmt"
	"log"
)

const (
	confPath = "config.gcfg"
)

// Config contains the values read from the config file at boot time
var Config struct {
	Global struct {
		Port             string
		StatsEnabled     bool
		LoggingEnabled   bool
		DeleteOldCookies bool
		ErrorFilePath    string
		DBHost           string
		DBUser           string
		DBPass           string
		DBRefreshPeriod  int
	}
	Stats struct {
		Server				string
		Port					int
		StatsCounter	int
		DCName string
	}
}

func init() {
	confFile := flag.String("conf", confPath, "Configuration file path")
	flag.Parse()
	fmt.Println("conffile:", *confFile)
	err := gcfg.ReadFileInto(&Config, *confFile)
	if err != nil {
		log.Panic("ERROR: conf.init:", err.Error())
	}
}
