package main

import (
	"io/ioutil"

	eventhub "github.com/Azure/azure-event-hubs-go"
	"gopkg.in/yaml.v2"
)

type ymlCfg struct {
	ConnStr string `yaml:"connEventHub"`
}

//GetHub ...
func GetHub() (*eventhub.Hub, error) {

	cfg := ymlCfg{}

	yamlFile, err := ioutil.ReadFile(".eventhub.yaml")
	if err != nil {
		return nil, err
	}

	err = yaml.Unmarshal(yamlFile, &cfg)
	if err != nil {
		return nil, err
	}

	hub, err := eventhub.NewHubFromConnectionString(cfg.ConnStr)
	if err != nil {
		return nil, err
	}
	return hub, nil

}
