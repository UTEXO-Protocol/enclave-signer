# Makefile Variables.
include config.mk

# Docker's BuildKit feature.
export DOCKER_BUILDKIT=1

.PHONY: build_parent push_parent build_enclave push_enclave build_enclave_dev push_enclave_dev docker docker_dev help

build_parent: ## Build parent adapter docker image.
	docker build -f ./build/Dockerfile.parent -t $(IMAGE_PARENT_BACKUP) . && \
	docker build -f ./build/Dockerfile.parent -t $(IMAGE_PARENT_LATEST) .

push_parent: ## Push parent adapter docker image.
	docker push $(IMAGE_PARENT_BACKUP) && \
	docker push $(IMAGE_PARENT_LATEST)

build_enclave: ## Build enclave docker image (production, vsock+rgb).
	docker build -f ./build/Dockerfile.enclave -t $(IMAGE_ENCLAVE_BACKUP) . && \
	docker build -f ./build/Dockerfile.enclave -t $(IMAGE_ENCLAVE_LATEST) .

push_enclave: ## Push enclave docker image.
	docker push $(IMAGE_ENCLAVE_BACKUP) && \
	docker push $(IMAGE_ENCLAVE_LATEST)

build_enclave_dev: ## Build enclave dev docker image (TCP, no vsock).
	docker build -f ./build/Dockerfile.enclave-dev -t $(IMAGE_ENCLAVE_DEV_BACKUP) . && \
	docker build -f ./build/Dockerfile.enclave-dev -t $(IMAGE_ENCLAVE_DEV_LATEST) .

push_enclave_dev: ## Push enclave dev docker image.
	docker push $(IMAGE_ENCLAVE_DEV_BACKUP) && \
	docker push $(IMAGE_ENCLAVE_DEV_LATEST)

docker: ## Build and push all production docker images.
	$(MAKE) build_parent push_parent build_enclave push_enclave

docker_dev: ## Build and push all dev docker images (parent + enclave-dev).
	$(MAKE) build_parent push_parent build_enclave_dev push_enclave_dev

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
