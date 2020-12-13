package main

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"time"

	eventhub "github.com/Azure/azure-event-hubs-go"
)

func main() {

	hub, err := GetHub()
	if err != nil {
		log.Fatalln(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	/*
			// read file
			//data, err := ioutil.ReadFile("pc.json")
			if err != nil {
				fmt.Print(err)
			}
		     s := string(data)

	*/

	for i := 1; i <= 3; i++ {

		now := time.Now()

		s := "msg" + strconv.Itoa(i) + " " + now.Format("2006-01-02 15:04:05")

		time.Sleep(5 * time.Second)

		err = hub.Send(ctx, eventhub.NewEventFromString(s))
		if err != nil {
			fmt.Println(err)
			return
		}

		fmt.Println(s)

	}

}
