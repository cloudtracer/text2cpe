# text2cpe

Reversed sorta implementation of CPE Name detection in ShoVAT based on research paper
Original Paper: http://www.ibs.ro/~bela/Papers/SCN2015.pdf


Could probably use some tuning, some CPE names are too generic like vmware:server and cause some false positives. Right now if I see to many of the same false positive that should be catching I'll remove the CPE identifier from the uniq_cpes file.


Here is the usage:

```
Text2CPE

  Reads banners from Shodan or Censys.io scan results and attempts to match the
  banner to a particular CPE. Based on ShoVAT paper.                            

Options

  -i, --input-file file    Shodan or Censys file to read.
  -o, --output-file file   Output file to save results.   
  -h, --help               Print this usage guide.        

Examples

  Read file and save results   $ node text2cpe.js -i /my/path/to/input -o       
                               /my/path/to/output                               

  Follow: @ThreatPinch for updates.
```

Here is some [sample CSV output](https://github.com/cloudtracer/text2cpe/blob/master/sample.csv) from the first few lines of the file.
