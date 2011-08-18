#!/bin/bash

wsname=$(basename $PWD)

files=".project-template .cproject-template \
    usr/src/uts/.project-template usr/src/uts/.cproject-template"

for file in $files; do
	sed s/template/"$wsname"/ $file > ${file%%-template}
done

echo "The following projects are ready to import to Eclipse:"
echo "$wsname        $PWD"
echo "$wsname-uts    $PWD/usr/src/uts"
