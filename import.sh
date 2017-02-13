#!/bin/bash


OUTPUT="$(sed  -n '3s/<\(.*\)>/<xsl:template match=\"\1\">/p' $1)"
eval "sed -i '2s/<.*/$OUTPUT/' transform.xsl"
cat headers.txt > CSV2
eval "xsltproc transform.xsl $1 >> CSV2"
eval "sed '2,3d' CSV2 > CSV"
eval "rm CSV2"



