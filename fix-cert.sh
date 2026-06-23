#!/bin/bash
cat << 'CONF' > openssl.cnf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name
[req_distinguished_name]
[ v3_req ]
basicConstraints = CA:TRUE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage = serverAuth
subjectAltName = @alt_names
[alt_names]
DNS.1 = pod-security-webhook
DNS.2 = pod-security-webhook.webhook-system
DNS.3 = pod-security-webhook.webhook-system.svc
CONF

openssl genrsa -out tls.key 2048
openssl req -new -key tls.key -subj "/CN=pod-security-webhook.webhook-system.svc" -config openssl.cnf -out tls.csr
openssl x509 -req -in tls.csr -signkey tls.key -out tls.crt -days 3650 -extensions v3_req -extfile openssl.cnf

kubectl create secret tls pod-security-webhook-tls --cert=tls.crt --key=tls.key -n webhook-system --dry-run=client -o yaml | kubectl apply -f -
kubectl delete pods -n webhook-system -l app=pod-security-webhook
