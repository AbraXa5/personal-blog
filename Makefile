CONTENT_DIR=content/blog
LAST_FILE=.last_post

# ===== START DEV SERVER (manual) =====
dev:
	hugo server -D --bind 0.0.0.0 --disableFastRender

# ===== CREATE NEW BLOG POST =====
new:
	@if [ -z "$(filter-out $@,$(MAKECMDGOALS))" ]; then \
		echo "Usage: make new \"My Blog Title\""; \
		exit 1; \
	fi
	$(eval TITLE := $(filter-out $@,$(MAKECMDGOALS)))
	$(eval SLUG := $(shell echo "$(TITLE)" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9 ]//g' | sed 's/ /-/g'))
	hugo new blog/$(SLUG)/index.md
	mkdir -p $(CONTENT_DIR)/$(SLUG)/images
	echo "$(SLUG)" > $(LAST_FILE)
	echo "Created blog: $(SLUG)"
	@echo "Opening the new post in VS Code..."
	code $(CONTENT_DIR)/$(SLUG)/index.md

# Trick to allow quoted arguments
%:
	@:

# ===== PUBLISH BLOG =====
push:
	@if [ ! -f $(LAST_FILE) ]; then \
		echo "No recent post found. Use 'make new \"Title\"' first."; \
		exit 1; \
	fi
	$(eval SLUG := $(shell cat $(LAST_FILE)))
	git add .
	git diff --cached --quiet && echo "Nothing to publish." && exit 0 || true
	git commit -m "Add blog for $(SLUG)"
	git push
	echo "Published 🚀"
