# SPDX-License-Identifier: AGPL-3.0-or-later
# SPDX-FileCopyrightText: 2025 Hyperpolymath
#
# Svalinn Vault Core - ATS Build System

PATSCC = patscc
PATSOPT = patsopt
ATSCC2JS = atscc2js

# ATS compiler flags - maximum safety
PATSCCOPTS = -O2 -flto
PATSCCOPTS += -D_FORTIFY_SOURCE=2
PATSCCOPTS += -fstack-protector-strong
PATSCCOPTS += -fPIE -pie
PATSCCOPTS += -Wl,-z,relro,-z,now

# Source files
SATS_FILES = $(wildcard SATS/*.sats)
DATS_FILES = $(wildcard DATS/*.dats)
HATS_FILES = $(wildcard HATS/*.hats)

# Object files
OBJS = $(DATS_FILES:.dats=_dats.o)

# Main target
TARGET = svalinn-vault-core

.PHONY: all clean typecheck test

all: typecheck $(TARGET)

# Type checking only (no code generation)
typecheck:
	@echo "=== Type checking ATS sources ==="
	@for f in $(SATS_FILES); do \
		echo "Checking $$f..."; \
		$(PATSOPT) --typecheck-only -s $$f || exit 1; \
	done
	@for f in $(DATS_FILES); do \
		echo "Checking $$f..."; \
		$(PATSOPT) --typecheck-only -d $$f || exit 1; \
	done
	@echo "=== All type checks passed ==="

# Compile to executable
$(TARGET): $(OBJS)
	$(PATSCC) $(PATSCCOPTS) -o $@ $^ -lssl -lcrypto -lblake3

# Pattern rule for .dats -> _dats.o
%_dats.o: %.dats $(SATS_FILES) $(HATS_FILES)
	$(PATSCC) $(PATSCCOPTS) -c -o $@ $<

# Clean build artifacts
clean:
	rm -f $(TARGET) $(OBJS)
	rm -f *_dats.c *_sats.c
	rm -f DATS/*_dats.c DATS/*_dats.o
	rm -f SATS/*_sats.c

# Run tests
test: $(TARGET)
	./$(TARGET) --test

# Install
install: $(TARGET)
	install -Dm755 $(TARGET) $(DESTDIR)/usr/bin/$(TARGET)

# Generate C code only (for inspection)
c-only:
	@for f in $(DATS_FILES); do \
		echo "Generating C for $$f..."; \
		$(PATSOPT) -o $${f%.dats}_dats.c -d $$f; \
	done
