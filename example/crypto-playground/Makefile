PYTHON ?= python3
VENV   ?= .venv
BIN    := $(VENV)/bin
PORT   ?= 8501

.PHONY: help venv install run start dev clean

help:
	@echo "Crypto Playground (Streamlit)"
	@echo ""
	@echo "Targets:"
	@echo "  install   Create a virtualenv and install dependencies"
	@echo "  run       Run the app (installs deps first if needed)"
	@echo "  start     Alias for 'run'"
	@echo "  dev       Run with auto-reload on file changes"
	@echo "  clean     Remove the virtualenv"
	@echo ""
	@echo "Variables: PYTHON=$(PYTHON)  VENV=$(VENV)  PORT=$(PORT)"

$(BIN)/streamlit: | $(VENV)
	$(BIN)/pip install --upgrade pip
	$(BIN)/pip install -r requirements.txt

$(VENV):
	$(PYTHON) -m venv $(VENV)

venv: $(VENV)

install: $(BIN)/streamlit
	@echo "Dependencies installed in $(VENV)"

run start: install
	$(BIN)/streamlit run app.py --server.port $(PORT)

dev: install
	$(BIN)/streamlit run app.py --server.port $(PORT) --server.runOnSave true

clean:
	rm -rf $(VENV)
