package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	eventhub "github.com/Azure/azure-event-hubs-go"
	//	"github.com/zen37/cpd/event_hub"
)

func main() {

	hub, err := GetHub()
	if err != nil {
		log.Fatalln(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// get info about the hub, particularly number and IDs of partitions
	info1, err := hub.GetRuntimeInformation(ctx)
	if err != nil {
		log.Fatalf("failed to get runtime info: %s\n", err)
	}
	fmt.Printf("Partition count: %v\nPath: %v\nCreated At: %v\nPartitionIDs %v\n", info1.PartitionCount, info1.Path, info1.CreatedAt, info1.PartitionIDs)

	fmt.Println()

	var arg1 string
	if len(os.Args) == 2 {
		arg1 = os.Args[1]
	}
	if arg1 == "p" {
		for _, p := range info1.PartitionIDs {
			// get info about the hub, particularly number and IDs of partitions
			info2, err := hub.GetPartitionInformation(ctx, p)
			if err != nil {
				log.Fatalf("failed to get runtime info: %s\n", err)
			}

			fmt.Printf("HubPath : %v\nPartitionID: %v\nBeginningSequenceNumber: %v\nLastSequenceNumber: %v\nLastEnqueuedOffset: %v\nLastEnqueuedTimeUtc: %v\n",
				info2.HubPath, info2.PartitionID, info2.BeginningSequenceNumber, info2.LastSequenceNumber, info2.LastEnqueuedOffset, info2.LastEnqueuedTimeUtc)
			fmt.Println()
		}
		os.Exit(0)
	}
	// set up wait group to wait for expected message
	eventReceived := make(chan struct{})

	// declare handler for incoming events
	handler := func(ctx context.Context, event *eventhub.Event) error {
		fmt.Printf("received: %s\n", string(event.Data))
		// notify channel that event was received
		eventReceived <- struct{}{}
		return nil
	}

	for _, partitionID := range info1.PartitionIDs {
		fmt.Println("PartitionID = ", partitionID)
		//_, err = hub.Receive(ctx, partitionID, handler)
		_, err := hub.Receive(ctx, partitionID, handler, eventhub.ReceiveFromTimestamp(time.Now().Add(-time.Hour*6)))
		if err != nil {
			log.Fatalf("failed to receive for partition ID %s: %s\n", partitionID, err)
			return
		}
	}

	<-eventReceived
	err = hub.Close(ctx)
	if err != nil {
		fmt.Println(err)
		return
	}
}

/*

		exit := make(chan struct{})
		handler := func(ctx context.Context, event *eventhub.Event) error {
			text := string(event.Data)
			fmt.Println(text)
			exit <- struct{}{}
			return nil
		}


		<-exit
		err = hub.Close(ctx)
		if err != nil {
			fmt.Println(err)
			return
		}

			select {
	case <-eventReceived:
	case err := <-ctx.Done():
		log.Fatalf("context cancelled before event received: %s\n", err)
	}

*/
