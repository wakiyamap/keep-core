#!/bin/bash

# Parses the Truffle artifacts
# and lists the deployed address of each contract
# Output format: 
# <name> <hex address | null>

# Example:
# Address null
# AddressArrayUtils null
# AltBn128 0xf553dB2F8169849a497010f7a96dfF39e8767823
# BLS 0x09e26a5606CE0F520253D3790315F5B0cBCC8804


if ! [ -x "$(command -v jq)" ]; then
  echo 'WARNING: jq command is not available'
  echo 'WARNING: please install from https://stedolan.github.io/jq/download/'
  exit 1
fi

TRUFFLE_BUILD_PATH=../contracts/solidity/build/contracts

for CONTRACT in $TRUFFLE_BUILD_PATH/*.json
do
    JSON=$(cat $CONTRACT)
    NAME=$(echo $JSON | jq -r '.contractName')
    ADDRESS=$(echo $JSON | jq -r '.networks["1101"].address')
    echo $NAME $ADDRESS;
done