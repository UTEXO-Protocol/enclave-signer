# Variables.
ENVIRONMENT             ?=
IMAGE_TAG               ?= latest
REGISTRY_HOST           ?= ghcr.io/utexo-protocol
CURRENT_DATE_TIME       := $(shell date +'%Y-%m-%d')
LATEST_COMMIT           := $(shell git rev-parse --short HEAD)

# Image names.
PARENT_IMAGE      := utexo-bridge-parent

# Variables for build.
IMAGE_PARENT_BACKUP      = $(REGISTRY_HOST)/$(PARENT_IMAGE)$(ENVIRONMENT):$(CURRENT_DATE_TIME)-$(LATEST_COMMIT)
IMAGE_PARENT_LATEST      = $(REGISTRY_HOST)/$(PARENT_IMAGE)$(ENVIRONMENT):$(IMAGE_TAG)
# Dev parent: same image, own tags, so it never lands on :latest.
IMAGE_PARENT_DEV_BACKUP  = $(REGISTRY_HOST)/$(PARENT_IMAGE)$(ENVIRONMENT):$(CURRENT_DATE_TIME)-$(LATEST_COMMIT)-dev
IMAGE_PARENT_DEV_LATEST  = $(REGISTRY_HOST)/$(PARENT_IMAGE)$(ENVIRONMENT):dev
