if ping -q -c 1 -W 1 8.8.8.8 >/dev/null; then
  apt-get update
  if [ -d "/var/log/sumologic-vmware" ]; then
    echo "Removing old temp repo directory."
    sudo rm -r /var/log/sumologic-vmware
  fi
  cd ..
  echo "Cloning Sumo Logic vSphere scripts."
  sudo git clone https://github.com/SumoLogic/sumologic-vmware
  if [ -d "/var/log/vmware" ]; then
    echo "Backing up old script installation."
    sudo mv /var/log/vmware /var/log/vmware_$(date -d "today" +"%Y%m%d%H%M")
  fi
  sudo mv sumologic-vmware/vsphere /var/log/vmware
  sudo chmod -R 777 /var/log/vmware
else
  echo "Unable to connect, please check network settings."
fi