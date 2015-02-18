#!/bin/bash 
if [ -d switchyard ]; then
  cd switchyard
  git pull
  cd ..
else
  git clone https://github.com/jsommers/switchyard
fi
sudo pip3 install -q -r switchyard/requirements.txt
