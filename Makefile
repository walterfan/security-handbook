POETRY ?= poetry
SPHINXBUILD ?= $(POETRY) run sphinx-build
SPHINXOPTS ?=
SOURCEDIR ?= doc/source
BUILDDIR ?= doc/build
HTMLDIR := $(BUILDDIR)/html
PAGES_URL ?= https://walterfan.github.io/security-handbook/

.PHONY: help install html build clean serve publish pages-artifact

help:
	@echo "Security Handbook documentation"
	@echo ""
	@echo "Targets:"
	@echo "  install        Install Poetry docs dependencies"
	@echo "  html, build    Build the Sphinx HTML book"
	@echo "  serve          Build and serve the book locally"
	@echo "  clean          Remove generated Sphinx output"
	@echo "  publish        Build the GitHub Pages artifact locally"
	@echo ""
	@echo "Published URL: $(PAGES_URL)"

install:
	$(POETRY) install --only docs --no-root

html build: install
	$(SPHINXBUILD) -b html "$(SOURCEDIR)" "$(HTMLDIR)" $(SPHINXOPTS)
	@touch "$(HTMLDIR)/.nojekyll"
	@echo "Built $(HTMLDIR)"

pages-artifact publish: html
	@echo "GitHub Pages artifact is ready in $(HTMLDIR)"
	@echo "Push to the repository to publish via GitHub Actions: $(PAGES_URL)"

serve: html
	cd "$(HTMLDIR)" && python3 -m http.server 8000

clean:
	rm -rf "$(BUILDDIR)"
