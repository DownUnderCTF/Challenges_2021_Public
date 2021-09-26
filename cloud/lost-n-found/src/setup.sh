#!/bin/bash

SERVICE_ACCOUNT_NAME=legacy-svc-account
PROJECT_NAME=ductf-lost-n-found

gcloud config set project ${PROJECT_NAME}

# Enable APIs
gcloud services enable cloudkms.googleapis.com secretmanager.googleapis.com

# Create key ring

gcloud kms keyrings create empty-keyring --location global # This is so they get a hint to look at KMS
gcloud kms keyrings create wardens-locks --location australia-southeast2 # The real keyring

# Create multiple keys 

gcloud kms keys create a-small-key      --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-golden-key     --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create an-iron-key      --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-bronze-key     --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-silver-key     --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-diamond-key    --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-filthy-key     --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-jail-key       --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-northern-key   --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-secret-key     --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-smart-key      --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-big-key        --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-fat-key        --keyring wardens-locks --location australia-southeast2 --purpose "encryption"
gcloud kms keys create a-key-key        --keyring wardens-locks --location australia-southeast2 --purpose "encryption"

# Disable all keys except for one

# Encrypt the flag with the key
gcloud kms encrypt --keyring wardens-locks --key a-silver-key --location australia-southeast2 --plaintext-file ./flag.txt --ciphertext-file=./cipher.enc
base64 -w 0 ./cipher.enc > cipher.enc.b64 

# Store the base64 encrypted flag as a secret
gcloud secrets create unused_data --data-file=cipher.enc.b64    

# Create the service account

gcloud iam service-accounts create ${SERVICE_ACCOUNT_NAME} --description="Useless account to protect from takeovers"

# Create role with required permissions
gcloud iam roles create Warden --project=${PROJECT_NAME} --title Warden --stage GA --permissions cloudkms.cryptoKeyVersions.useToDecrypt,cloudkms.cryptoKeys.get,cloudkms.cryptoKeys.list,cloudkms.keyRings.get,cloudkms.keyRings.list,cloudkms.locations.get,cloudkms.locations.list

# Create the IAM binding with the correct roles
gcloud projects add-iam-policy-binding ${PROJECT_NAME} \
    --member=serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_NAME}.iam.gserviceaccount.com --role projects/${PROJECT_NAME}/roles/Warden

gcloud projects add-iam-policy-binding ${PROJECT_NAME} \
    --member=serviceAccount:${SERVICE_ACCOUNT_NAME}@${PROJECT_NAME}.iam.gserviceaccount.com --role roles/secretmanager.viewer

# Get the Service account key.

gcloud iam service-accounts keys create legacy.json --iam-account=${SERVICE_ACCOUNT_NAME}@${PROJECT_NAME}.iam.gserviceaccount.com