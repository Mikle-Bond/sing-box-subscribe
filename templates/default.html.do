exec >&2
src="$1.pug"
dst="$3"
redo-ifchange "$src"
pug --pretty < "$src" > "$dst"

