SHELL := /bin/bash

include $(shell test -f .tardigrade-ci || curl -sSL -o .tardigrade-ci "https://raw.githubusercontent.com/plus3it/tardigrade-ci/master/bootstrap/Makefile.bootstrap"; echo .tardigrade-ci)

export AWS_DEFAULT_REGION

semver/install: | guard/program/npm
	@ echo "[$@]: Installing $(@D)..."
	npm install -g semver
	@ echo "[$@]: Completed successfully!"

.PHONY: release/%
release/%: PRIOR_VERSION := $(shell git describe --abbrev=0 --tags 2> /dev/null)
release/%: RELEASE_VERSION := $(shell grep '^current_version' .bumpversion.cfg | sed 's/^.*= //')
release/%: | guard/program/semver

release/test: | guard/program/semver
	@ echo "[$@]: Checking version tag (prior) against version file (release)..."
	@ echo "[$@]: PRIOR_VERSION = $(PRIOR_VERSION)"
	@ echo "[$@]: RELEASE_VERSION = $(RELEASE_VERSION)"
	+$(if $(PRIOR_VERSION),semver -r '> $(PRIOR_VERSION)' '$(RELEASE_VERSION)' > /dev/null)

release/tag:
	echo "[$@]: Releasing version $(RELEASE_VERSION)"
	git tag $(RELEASE_VERSION)
	git push --tags

event:
	@ if [ -n "$(IS_REVIEW)" ]; then \
		$(MAKE) event/review; \
	elif [ -n "$(IS_BRANCH)" ]; then \
		$(MAKE) event/branch; \
	elif [ -n "$(IS_TAG)" ]; then \
		$(MAKE) event/tag; \
	else \
		echo "[$@] ERROR: Unknown event type!"; \
		exit 1; \
	fi
.PHONY: event

event/%: CONFIGS := .

event/review:
	@ echo "[$@] REVIEW: Event is a pull request review..."
	@ echo "[$@] REVIEW: Checking whether a release will be triggered..."
	@ if $(MAKE) release/test 2> /dev/null; then \
		$(MAKE) event/review/release; \
	else \
		$(MAKE) event/review/norelease; \
	fi

event/review/release:
	@ echo "[$@]: REVIEW: Will release new version when merged; see plan output for changes."

event/review/norelease:
	@ echo "[$@]: REVIEW: Version has not incremented; any planned changes **will not** be applied when merged."

event/branch:
	@ echo "[$@] BRANCH: Handling event on branch '$(IS_BRANCH)'..."
	@ echo "[$@] BRANCH: Checking the release condition..."
	@ if $(MAKE) release/test 2> /dev/null; then \
		$(MAKE) event/branch/release; \
	else \
		$(MAKE) event/branch/norelease; \
	fi

event/branch/norelease:
	echo "[$@]: BRANCH: Version has not incremented, skipping tag release"

event/branch/release:
	@ echo "[$@] BRANCH: Handling deploy for event on branch '$(IS_BRANCH)'..."
	$(MAKE) release/tag

event/tag:
	@ echo "[$@] TAG: Handling deploy for event on tag '$(IS_TAG)'..."
.PHONY: event/%
