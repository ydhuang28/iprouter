#!/bin/bash 
if [ -d switchyard ]; then
  echo "Updating switchyard code"
  cd switchyard
  git pull
  cd ..
else
  echo "Cloning switchyard code"
  git clone https://github.com/jsommers/switchyard
fi
echo "Installing any necessary Python libraries (this may take a moment)"
sudo pip3 install -q -r switchyard/requirements.txt
