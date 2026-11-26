IMAGE ?= treeward:mvp
CONTEXT ?= kind-treeward
NAMESPACE ?= treeward

.PHONY: build build-local image load deploy wait demo logs status port-forward

build-local:
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/api ./cmd/api
	CGO_ENABLED=0 go build -o bin/connector ./cmd/connector
	CGO_ENABLED=0 go build -o bin/agent ./cmd/agent
	CGO_ENABLED=0 go build -o bin/treeward ./cmd/treeward

image:
	docker build -t $(IMAGE) .

load: image
	kind load docker-image $(IMAGE) --name treeward

deploy: load
	kubectl --context $(CONTEXT) apply -f deploy/k8s/treeward.yaml
	kubectl --context $(CONTEXT) -n $(NAMESPACE) rollout status deploy/treeward-api --timeout=120s
	kubectl --context $(CONTEXT) -n $(NAMESPACE) rollout status deploy/treeward-connector --timeout=120s
	kubectl --context $(CONTEXT) -n $(NAMESPACE) rollout status ds/treeward-agent --timeout=120s

wait:
	kubectl --context $(CONTEXT) -n $(NAMESPACE) wait --for=condition=available deploy/treeward-api --timeout=120s

status:
	kubectl --context $(CONTEXT) -n $(NAMESPACE) get pods,svc

logs:
	kubectl --context $(CONTEXT) -n $(NAMESPACE) logs -l app=treeward-api --tail=50
	kubectl --context $(CONTEXT) -n $(NAMESPACE) logs -l app=treeward-connector --tail=50
	kubectl --context $(CONTEXT) -n $(NAMESPACE) logs -l app=treeward-agent --tail=50

port-forward:
	kubectl --context $(CONTEXT) -n $(NAMESPACE) port-forward svc/treeward-api 8080:8080

demo: build-local
	./scripts/demo.sh
