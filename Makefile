# Makefile Variables.
include config.mk

# Docker's BuildKit feature.
export DOCKER_BUILDKIT=1

# Token stays in a BuildKit secret; override with per-repo --secret flags if needed.
DOCKER_AUTH_ARGS ?= --secret id=github_token,env=GITHUB_TOKEN

# Public KMS pins are exported only for the two production swap targets.
# Docker reads --build-arg NAME from the environment; values never become shell
# source through Make expansion. Required pins may come from env or make args.
SWAP_KMS_ALLOW_CREATE ?= 0
SWAP_KMS_EXPECTED_EVM_ADDRESS ?=
SWAP_KMS_BUILD_ARGS = --build-arg SWAP_KMS_KEY_ARN --build-arg SWAP_KMS_REGION --build-arg SWAP_KMS_SEED_ID --build-arg SWAP_KMS_ALLOW_CREATE --build-arg SWAP_KMS_EXPECTED_EVM_ADDRESS
build_enclave build_enclave_rgb: export SWAP_KMS_KEY_ARN := $(SWAP_KMS_KEY_ARN)
build_enclave build_enclave_rgb: export SWAP_KMS_REGION := $(SWAP_KMS_REGION)
build_enclave build_enclave_rgb: export SWAP_KMS_SEED_ID := $(SWAP_KMS_SEED_ID)
build_enclave build_enclave_rgb: export SWAP_KMS_ALLOW_CREATE := $(SWAP_KMS_ALLOW_CREATE)
build_enclave build_enclave_rgb: export SWAP_KMS_EXPECTED_EVM_ADDRESS := $(SWAP_KMS_EXPECTED_EVM_ADDRESS)

.PHONY: build_parent push_parent build_enclave push_enclave build_enclave_rgb push_enclave_rgb build_enclave_ccd push_enclave_ccd build_enclave_dev push_enclave_dev check_swap_kms_config docker docker_dev help

build_parent: ## Build parent adapter docker image.
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.parent -t $(IMAGE_PARENT_BACKUP) . && \
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.parent -t $(IMAGE_PARENT_LATEST) .

push_parent: ## Push parent adapter docker image.
	docker push $(IMAGE_PARENT_BACKUP) && \
	docker push $(IMAGE_PARENT_LATEST)

check_swap_kms_config:
	@: "$${SWAP_KMS_KEY_ARN:?SWAP_KMS_KEY_ARN required for RGB swap builds}" \
	   "$${SWAP_KMS_REGION:?SWAP_KMS_REGION required for RGB swap builds}" \
	   "$${SWAP_KMS_SEED_ID:?SWAP_KMS_SEED_ID required for RGB swap builds}"
	@case "$$SWAP_KMS_ALLOW_CREATE" in \
	  0) : "$${SWAP_KMS_EXPECTED_EVM_ADDRESS:?SWAP_KMS_EXPECTED_EVM_ADDRESS required for RGB swap recovery}" ;; \
	  1) test -z "$$SWAP_KMS_EXPECTED_EVM_ADDRESS" || { echo "Error: bootstrap cannot set SWAP_KMS_EXPECTED_EVM_ADDRESS" >&2; exit 1; } ;; \
	  *) echo "Error: SWAP_KMS_ALLOW_CREATE must be 0 or 1" >&2; exit 1 ;; esac

build_enclave: check_swap_kms_config ## Build combined enclave docker image (vsock+rgb+ccd+evm-rpc).
	docker build $(DOCKER_AUTH_ARGS) $(SWAP_KMS_BUILD_ARGS) -f ./build/Dockerfile.enclave -t $(IMAGE_ENCLAVE_BACKUP) . && \
	docker build $(DOCKER_AUTH_ARGS) $(SWAP_KMS_BUILD_ARGS) -f ./build/Dockerfile.enclave -t $(IMAGE_ENCLAVE_LATEST) .

push_enclave: ## Push combined enclave docker image.
	docker push $(IMAGE_ENCLAVE_BACKUP) && \
	docker push $(IMAGE_ENCLAVE_LATEST)

build_enclave_rgb: check_swap_kms_config ## Build RGB-only enclave docker image (vsock+rgb+evm-rpc).
	docker build $(DOCKER_AUTH_ARGS) $(SWAP_KMS_BUILD_ARGS) -f ./build/Dockerfile.enclave.rgb -t $(IMAGE_ENCLAVE_RGB_BACKUP) . && \
	docker build $(DOCKER_AUTH_ARGS) $(SWAP_KMS_BUILD_ARGS) -f ./build/Dockerfile.enclave.rgb -t $(IMAGE_ENCLAVE_RGB_LATEST) .

push_enclave_rgb: ## Push RGB-only enclave docker image.
	docker push $(IMAGE_ENCLAVE_RGB_BACKUP) && \
	docker push $(IMAGE_ENCLAVE_RGB_LATEST)

build_enclave_ccd: ## Build Concordium-only enclave docker image (vsock+ccd).
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.enclave.ccd -t $(IMAGE_ENCLAVE_CCD_BACKUP) . && \
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.enclave.ccd -t $(IMAGE_ENCLAVE_CCD_LATEST) .

push_enclave_ccd: ## Push Concordium-only enclave docker image.
	docker push $(IMAGE_ENCLAVE_CCD_BACKUP) && \
	docker push $(IMAGE_ENCLAVE_CCD_LATEST)

build_enclave_dev: ## Build enclave dev docker image (TCP, no vsock).
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.enclave-dev -t $(IMAGE_ENCLAVE_DEV_BACKUP) . && \
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.enclave-dev -t $(IMAGE_ENCLAVE_DEV_LATEST) .

push_enclave_dev: ## Push enclave dev docker image.
	docker push $(IMAGE_ENCLAVE_DEV_BACKUP) && \
	docker push $(IMAGE_ENCLAVE_DEV_LATEST)

docker: ## Build and push production images; requires the measured SWAP_KMS_* configuration (see README).
	$(MAKE) build_parent push_parent build_enclave push_enclave

docker_dev: ## Build and push all dev docker images (parent + enclave-dev).
	$(MAKE) build_parent push_parent build_enclave_dev push_enclave_dev

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
