#!/bin/sh

set -eu

if [ "$#" -ne 3 ]; then
	printf '%s\n' "usage: $0 RELEASE_DIRECTORY PYSPDXTOOLS EXPECTED_SPDX_TOOLS_VERSION" >&2
	exit 2
fi

distribution=$(CDPATH='' cd -- "$1" && pwd -P)
validator=$2
expected_version=$3
if [ ! -f "$validator" ] || [ ! -x "$validator" ]; then
	printf '%s\n' "SPDX validator is not an executable regular file: $validator" >&2
	exit 2
fi
validator=$(CDPATH='' cd -- "$(dirname -- "$validator")" && pwd -P)/$(basename -- "$validator")
python=$(dirname -- "$validator")/python
if [ ! -x "$python" ]; then
	printf '%s\n' "cannot identify the validator environment's Python interpreter" >&2
	exit 2
fi

actual_version=$(PYTHONNOUSERSITE=1 "$python" -c 'import importlib.metadata; print(importlib.metadata.version("spdx-tools"))')
if [ "$actual_version" != "$expected_version" ]; then
	printf '%s\n' "spdx-tools version mismatch: got $actual_version, want $expected_version" >&2
	exit 1
fi

count=0
for sbom in "$distribution"/*.spdx.json; do
	if [ ! -f "$sbom" ]; then
		printf '%s\n' "release distribution contains no external SPDX JSON documents" >&2
		exit 1
	fi
	PYTHONNOUSERSITE=1 "$validator" --infile "$sbom" --version SPDX-2.3
	count=$((count + 1))
done
if [ "$count" -ne 6 ]; then
	printf '%s\n' "validated $count SPDX documents, want exactly 6" >&2
	exit 1
fi

printf '%s\n' "all six SPDX 2.3 documents passed independent spdx-tools $actual_version validation"
