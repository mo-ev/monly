#! /bin/bash
#create and start the machine
docker-machine create -d virtualbox default

#We must stop the machine in order to modify some settings
docker-machine stop

#Enable USB
#vboxmanage modifyvm default --usb on
# OR, if you installed the extension pack, use USB 2.0
vboxmanage modifyvm default --usbehci on

# Go ahead and start the VM back up
docker-machine start

# Setup a usb filter so your device automatically gets connected to the Virtualbox VM.
# vboxmanage usbfilter add 0 --target default --name ios-device --vendorid 0x05AC --productid 0x12AB

#setup your terminal to use your new docker-machine
eval $(docker-machine env default)
