rm image/webhook-server

cd cmd/webhook-server

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o webhook-server main.go admission_controller.go

cp webhook-server ../../image/

cd ../../

kubectl delete ns webhook-demo

kubectl delete MutatingWebhookconfiguration demo-webhook

cd image/

docker build -t gautambaghel/art-ac:latest .

docker push gautambaghel/art-ac:latest

cd ..

./deploy.sh