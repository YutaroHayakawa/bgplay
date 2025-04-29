deploy-record: bgplay
	sudo containerlab -t topo.gotmpl --vars vars.yaml deploy
	docker cp bgplay clab-example-router1:/usr/local/bin/bgplay

deploy-replay: bgplay
	sudo containerlab -t topo.gotmpl deploy
	docker cp bgplay clab-example-router0:/usr/local/bin/bgplay

destroy:
	sudo containerlab -t topo.gotmpl destroy -c
	rm -f bgplay

bgplay:
	CGO_ENABLED=0 go build -o bgplay ../main.go
