#!/bin/bash


cat headers.txt > CSV
eval "xsltproc transform.xsl $1 >> CSV2"
eval "sed '2,3d' CSV2 > CSV"
eval "rm CSV2"



