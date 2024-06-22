#!/bin/bash
if [ "$(id -u)" == 0 ]; then echo "Please don't run as root." >&2; exit 1; fi
INSTALL_PATH=$(pwd)
apt update
sudo apt install sudo git curl unzip snap snapd fonts-roboto-unhinted fonts-inconsolata -yy
sudo apt install xfce4 xfce-terminal paper-icon-theme -yy
sudo apt install xserver-xorg-input-multitouch xserver-xorg-input-synaptics -yy

sudo apt install ftp python3 python3-pip nmap unzip python3-venv ssh \
proxychains4 freerdp2-x11 lightdm lightdm-settings slick-greeter libpcap-dev \
wget libssl-dev tcpdump smbclient imagemagick ghostscript \
simplescreenrecorder libcurl4-openssl-dev libssl-dev jq \
mariadb-client dirb whois sslsplit dnsrecon sipsak braa onesixtyone \
sipvicious build-essential make gcc fontconfig fonts-powerline \
wireshark vlc smbmap neofetch conky apache2 mariadb-server \
php net-tools htop gnupg2 wget gpg apt-transport-https code \
software-properties-common google-chrome-stable golang -yy


wget https://github.com/R0M-0X/Scripts/blob/005991c92d91f3e02be98fc74a4e840e3fa00c6a/_Assets/Deb/GTK/Nordic-darker.tar.xz
wget https://github.com/R0M-0X/Scripts/blob/005991c92d91f3e02be98fc74a4e840e3fa00c6a/_Assets/Wallpapers/wall2.jpg

tar -xvf Nordic-darker.tar.xz
cp -r Nordic-darker-v40/ /usr/share/themes/
sudo xfconf-query -c xsettings -p /Net/ThemeName -s Nordic-standard-buttons-v40
sudo xfconf-query -c xfwm4 -p /general/theme -s Nordic-standard-buttons-v40

mkdir -p /usr/share/wallpapers/
sudo cp wall2.jpg /usr/share/wallpapers/


wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo tee /etc/apt/trusted.gpg.d/google.asc >/dev/null
sudo echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/chrome.list
#wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb

## Apps 
snap install spotify
snap install bitwarden

## Visual Studio Code
sudo wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg
sudo install -D -o root -g root -m 644 packages.microsoft.gpg /etc/apt/keyrings/packages.microsoft.gpg
sudo sh -c 'echo "deb [arch=amd64,arm64,armhf signed-by=/etc/apt/keyrings/packages.microsoft.gpg] https://packages.microsoft.com/repos/code stable main" > /etc/apt/sources.list.d/vscode.list'
sudo rm -f packages.microsoft.gpg

sudo apt update 


#================= Change Boot logo ========================#
git clone https://github.com/adi1090x/plymouth-themes.git
cd plymouth-themes/pack_2
sudo cp -r deus_ex /usr/share/plymouth/themes/
cd $INSTALL_PATH
# check if theme exist in dir
sudo plymouth-set-default-theme -l
# now set the theme (angular, in this case) and rebuilt the initrd
sudo plymouth-set-default-theme -R deus_ex

#================== Change icons ===========================#
sudo apt update && apt install paper-icon-theme -yy
# set the icon theme
sudo gsettings set org.gnome.desktop.interface icon-theme "Paper-Mono-Dark"
# or the cursor theme
sudo gsettings set org.gnome.desktop.interface cursor-theme "Paper-Mono-Dark"
# XFCE
xfconf-query -c xsettings -p /Net/IconThemeName -s Paper-Mono-Dark


###### Tools Cyber

go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest


##### Dir
/root/


 