# Makefile Variables.
include config.mk

# Docker's BuildKit feature.
export DOCKER_BUILDKIT=1

# Private dependency of both workspaces (the rgb-lib-bfa mirror) and the token
# the build scripts require: both stay in BuildKit secrets.
DOCKER_AUTH_ARGS ?= --secret id=lib_key,env=RGB_LIB_BFA_DEPLOY_KEY --secret id=rgb_deps_token,env=RGB_PRIVATE_DEPS_TOKEN

# Pass public values through Docker's environment form, not shell interpolation.
IMAGE_ENCLAVE_MINT_BACKUP ?= $(REGISTRY_HOST)/utexo-bridge-enclave-mint$(ENVIRONMENT):$(CURRENT_DATE_TIME)-$(LATEST_COMMIT)
IMAGE_ENCLAVE_MINT_LATEST ?= $(REGISTRY_HOST)/utexo-bridge-enclave-mint$(ENVIRONMENT):$(IMAGE_TAG)
build_enclave_mint: export RGB_ASSET_ID := $(RGB_ASSET_ID)
build_enclave_mint: export KMS_ALLOWED_ACCOUNT_IDS := $(KMS_ALLOWED_ACCOUNT_IDS)

.PHONY: build_parent push_parent build_parent_dev push_parent_dev build_enclave_mint push_enclave_mint check_mint_config docker docker_dev help

build_parent: ## Build parent adapter docker image.
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.parent -t $(IMAGE_PARENT_BACKUP) . && \
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.parent -t $(IMAGE_PARENT_LATEST) .

push_parent: ## Push parent adapter docker image.
	docker push $(IMAGE_PARENT_BACKUP) && \
	docker push $(IMAGE_PARENT_LATEST)

build_parent_dev: ## Build parent dev image (debug, insecure-dev: plaintext gRPC, no mTLS). Same name, tags :dev and :<date>-<commit>-dev.
	docker build $(DOCKER_AUTH_ARGS) -f ./build/Dockerfile.parent \
		--build-arg CARGO_ARGS="--features insecure-dev" --build-arg PROFILE_DIR=debug \
		-t $(IMAGE_PARENT_DEV_BACKUP) -t $(IMAGE_PARENT_DEV_LATEST) .

push_parent_dev: ## Push parent dev image tags.
	docker push $(IMAGE_PARENT_DEV_BACKUP) && \
	docker push $(IMAGE_PARENT_DEV_LATEST)

check_mint_config:
	@: "$${RGB_ASSET_ID:?RGB_ASSET_ID required for RGB mint builds}"
	@: "$${KMS_ALLOWED_ACCOUNT_IDS:?KMS_ALLOWED_ACCOUNT_IDS required for RGB mint builds}"

build_enclave_mint: check_mint_config ## Build RGB mint signer image with KMS seed persistence.
	docker build $(DOCKER_AUTH_ARGS) --build-arg RGB_ASSET_ID --build-arg KMS_ALLOWED_ACCOUNT_IDS -f ./build/Dockerfile.enclave.mint -t $(IMAGE_ENCLAVE_MINT_BACKUP) . && \
	docker build $(DOCKER_AUTH_ARGS) --build-arg RGB_ASSET_ID --build-arg KMS_ALLOWED_ACCOUNT_IDS -f ./build/Dockerfile.enclave.mint -t $(IMAGE_ENCLAVE_MINT_LATEST) .

push_enclave_mint: ## Push RGB mint signer image.
	docker push $(IMAGE_ENCLAVE_MINT_BACKUP) && \
	docker push $(IMAGE_ENCLAVE_MINT_LATEST)

docker: ## Build and push the parent image.
	$(MAKE) build_parent push_parent

docker_dev: ## Build and push all dev docker images (parent-dev + enclave-dev).
	$(MAKE) build_parent_dev push_parent_dev

help: ## Show this help.
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
