#!/bin/bash

if [ -z `which java` ]
then
	echo "java not found, please install jdk11 or newer."
	exit 1
fi

if [ -z $1 ]
then
	echo
	echo "Please pass the name of the sample you want to execute as an argument"
	echo "Examples:-"
	echo "> run.sh LoginLogout.java"
	echo "> run.sh crypto_operations/EncryptUsing_AESCBCMode.java"
	echo "> run.sh slot_management/LoginLogoutUsingSlotLabel.java"
	echo
	exit 1
fi

java -cp /usr/safenet/lunaclient/jsp/lib/LunaProvider.jar:. -Djava.library.path=/usr/safenet/lunaclient/jsp/lib/ $1 $2 $3 $4 $5
