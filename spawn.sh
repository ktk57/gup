#!/bin/bash
#set -x
cd $GOPATH/src/github.com/pubmatic/pub-adserver/go/drproxy
pid=`ps -ef | grep drproxy | grep -v grep | awk '{print $2}'`
if [ "$pid" != "" ]
then
	echo "Another instance of drproxy running. Killing it."
	kill -9 $pid
fi
echo "Building drproxy"
go build
if [ -f drproxy ]
then
	echo "Build Successfull. Starting drproxy"
	export GOGC=5000
	nohup ./drproxy --conf=config.gcfg &
	echo "--------DONE--------"
else
	echo "Build failed"
fi
