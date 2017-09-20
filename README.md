# text2cpe

Reversed sorta implementation of CPE Name detection in ShoVAT based on research paper
Original Paper: http://www.ibs.ro/~bela/Papers/SCN2015.pdf

Run with: node index.js > ./out.csv

File name being read is hard coded, I originally ran it against the [critical_201303_22.json](https://scans.io/data/rapid7/sonar.cio/critical_201303_22.json.bz2) file with some interesting results. Could probably use some tuning by somebody that understands the math better, or has other ideas on how to do some fuzzy correlation. All the banners are ssdeep hashed as well.

Maybe if time presents itself in the future I will clean this up. For now I just wanted to get it checked into github so that it doesn't get lost.

Here is some [sample CSV output](https://github.com/cloudtracer/text2cpe/blob/master/sample.csv) from the first few lines of the file.
