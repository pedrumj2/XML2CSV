#!/bin/bash


cat headers.txt > CSV
eval "xsltproc transform.xsl $1 >> CSV"
eval "sed '2,3d' CSV > CSV2"



