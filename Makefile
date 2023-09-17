
mod-action-%:
	@echo "Run go mod ${*}...."
	GO111MODULE=on go mod $*
	@echo "Done go mod  ${*}"

mod: mod-action-verify mod-action-tidy mod-action-vendor mod-action-download mod-action-verify ## Download all dependencies
