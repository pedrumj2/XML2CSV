# XML2CSV
bash scripts for importing xml files into mysql. Apparently there is no easy way of importing XML files to mysql. I have previously
written a program for importing CSV files. This program converts the xml files into csv files which can later be imported using the other 
project. 

**Note:** This is mainly a utility function as most of the work is done by xsltproc. However due to the fact that this is part of a larger
project, the script helps in automating the process. 

#usage
1- Edit the xsl file

2- Make sure headers are correct in header.txt file

3- run the script with the name of the xml file as input

```bash
./import.sh file.xml
```
