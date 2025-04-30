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

record:
	docker exec -it clab-example-router1 bgplay record \
		--local-asn 65000 \
		--peer-addr 169.254.0.1 \
		--router-id 169.254.0.2 \
		test.bgpcap
	docker cp clab-example-router1:/root/test.bgpcap .

replay:
	docker cp test.bgpcap clab-example-router0:/root/test.bgpcap
	docker exec -it clab-example-router0 bgplay replay \
		--peer-addr 169.254.0.2 \
		test.bgpcap
