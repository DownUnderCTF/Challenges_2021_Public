#!/bin/bash

# Run this script to set up the challenge, update the below variables to what you like

PROJECT_NAME=cloudsupporthacks
CLUSTER_NAME=very-secure5
CONTAINER_NAME=lfi
ZONE=australia-southeast1-b
SERVICE_ACCOUNT_NAME=useless-account

gcloud config set project ${PROJECT_NAME}

# docker build -t gcr.io/${PROJECT_NAME}/lfi:latest .

# Need to enable, compute, gke, iam, build, 
gcloud services enable cloudbuild.googleapis.com compute.googleapis.com container.googleapis.com containerregistry.googleapis.com iam.googleapis.com

# Create, build and push the Vulnerable LFI container
gcloud builds submit --tag=gcr.io/${PROJECT_NAME}/${CONTAINER_NAME}:latest src/          

# Create useless service account that the nodes will runas
gcloud iam service-accounts create ${SERVICE_ACCOUNT_NAME} --description="Useless account to protect from takeovers"

# Create the cluster with 1 node in the one zone
gcloud container clusters create ${CLUSTER_NAME} --num-nodes=1 --zone australia-southeast1-b --service-account ${SERVICE_ACCOUNT_NAME}@${PROJECT_NAME}.iam.gserviceaccount.com

# Load credentials for the cluster into kubectl
gcloud container clusters get-credentials ${CLUSTER_NAME} --zone australia-southeast1-b

# Format the config file with the project name and container name
cp src/config.yaml src/config-formatted.yaml
sed -i "s/{{PROJECT_NAME}}/${PROJECT_NAME}/g" src/config-formatted.yaml
sed -i "s/{{CONTAINER_NAME}}/${CONTAINER_NAME}/g" src/config-formatted.yaml

# Apply the config and deploy the workload
kubectl apply -f src/config-formatted.yaml

# Delete created config.yaml file
rm src/config-formatted.yaml

# Apply permission updates and store the secret flag
kubectl apply -f src/permission.yaml

# Enable Traffic to port 30000 on the nodes.
gcloud compute firewall-rules create test-node-port --allow tcp:30000

# Output the Node IP 
kubectl get nodes --output wide  

external_ip=$(kubectl get nodes --output jsonpath="{.items[0].status.addresses[1].address}")

echo "Access the challenge at: http://${external_ip}:30000"

cluster_external_ip=$(gcloud container clusters describe ${CLUSTER_NAME} --zone ${ZONE} --format='get(endpoint)')

echo "Cluster External API located at https://${cluster_external_ip}"