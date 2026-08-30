#!/bin/sh
set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_dir=$(CDPATH='' cd -- "$script_dir/.." && pwd)
output=${1:-"$project_dir/demo-case"}
binary=${2:-"$project_dir/bin/cirewind"}

exec "$binary" demo --out "$output"
