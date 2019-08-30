#!/bin/sh
PID=`adb shell ps | grep test-wvplayer | awk '{print $2}'`
adb shell kill -9 $PID
