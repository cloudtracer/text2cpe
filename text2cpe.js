/*
Author:         Development@ThreatPinch.com
Description:    Reversed sorta implementation of CPE Name detection in ShoVAT based on research paper
Original Paper: http://www.ibs.ro/~bela/Papers/SCN2015.pdf

*/

var bluebird = require('bluebird');
var _ = require('underscore');
var xml2js = require('xml2js');
var fs = require('fs');
var PCRE = require('pcre-to-regexp');
var ssdeep = require('ssdeep.js');
const cli_usage = require('command-line-usage');
const cli_args = require('command-line-args');
const zlib = require('zlib');

const base_path = __dirname;

var results_write_stream;

var option_list = [
  {
    name: 'input-file',
    alias: 'i',
    type: String,
    typeLabel: '[underline]{file}',
    description: 'Shodan or Censys file to read.'
  },
  {
    name: 'output-file',
    alias: 'o',
    type: String,
    typeLabel: '[underline]{file}',
    description: 'Output file to save results.'
  },
  {
    name: 'help',
    alias: "h",
    type: Boolean,
    defaultOption: true,
    description: 'Print this usage guide.'
  }
];

var sections = [
  {
    header: 'Text2CPE',
    content: 'Reads banners from Shodan or Censys.io scan results and attempts to match the banner to a particular CPE. Based on ShoVAT paper.'
  },
  {
    header: 'Options',
    optionList: option_list
  },
  {
    header: 'Examples',
    content: [
      {
        desc: 'Read file and save results',
        example: '$ node text2cpe.js -i /my/path/to/input -o /my/path/to/output'
      }
    ]
  },
  {
    content: 'Follow: @ThreatPinch for updates.'
  }
];

var usage = cli_usage(sections);
var nmapIdentification = {};
var ztagIdentification = {};
var recogIdentification = {};

var cpeHashes = {};


function Main(){
  args = cli_args(option_list, { partial: true });
  const usage = cli_usage(sections);
  //console.log(args);
  if(args['help'] || Object.keys(args).length == 0 ){
    console.log(usage);
    return true;
  }

  if(!args['input-file'] || !args['output-file']){
    console.log(usage);
    console.log("Error: -i or -o not set.");

  }
  if(args['output-file']){
    if(fs.existsSync(args['output-file'])){
      console.warn("WARN: " + args['output-file'] + " already exists, overwriting...");
      fs.unlinkSync(args['output-file']);
    }
    results_write_stream = require('fs').createWriteStream(args['output-file'],{ flags:'a' });
  }

  if(args['input-file']){
     ProcessBanners(args['input-file'], results_write_stream);
  }
}

function WriteToStream(line, stream){
  stream.write(line +"\n");
}

function GetCPEVersionMatches(banner){
  var versionRegex = new RegExp("(\\d+\\.(\\d|\\.)*\\d+)","g"),
      matches,
      values = [];

  while (matches = versionRegex.exec(banner)) {
      var splits = matches[1].split(".");
      var new_versions = "";
      for(var i = 1; i < splits.length; i++){
        if(i == 1) new_versions = splits[0];
        new_versions = new_versions + "." + splits[i];
        values.push(new_versions);
      }
      //values.push(decodeURI(matches[1]));
  }
  //return longer matches first
  if(values){
    values.sort(function(a, b){
      return b.length - a.length;
    });
  }
  return values;
}

function GetBannerVersionMatches(banner){
  var versionRegex = new RegExp("(\\d+\\.(\\d|\\.)*\\d+)","g"),
      matches,
      values = [];

  while (matches = versionRegex.exec(banner)) {
      values.push(decodeURI(matches[1]));
  }
  //return longer matches first
  if(values){
    values.sort(function(a, b){
      return b.length - a.length;
    });
  }
  return values;
}

function escapeRegExp(str) {
  return str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|]/g, "\\$&");
}

function convertNMAPRegexToJavascriptRegex(str) {
  /*
  str = str.replace(/\\d/g, "\\\\d");
  str = str.replace(/\\s/g, "\\\\s");
  str = str.replace(/\\w/g, "\\\\w");
  str = str.replace(/\\r\\n/g, "[\\\\s\\\\S]*");
  str = str.replace(/\r\n/g, "[\\\\s\\\\S]*");
  */
  //str = escapeRegExp(str);
  //str = str.replace(/\\\\r\\\\n/g, "[\\\\s\\\\S]*");
  //str = str.replace(/\\r\\n/g, "[\\\\s\\\\S]*");


  //str = str.replace(/\\/gm, "\\\\");
  //str = str.replace(/\\\\\(/gm, "\\(");
  //str = str.replace(/\\\\\)/gm, "\\)");
  //str = str.replace(/\\\\\[/gm, "\\[");
  //str = str.replace(/\\\\\]/gm, "\\]");
  //str = str.replace(/\\\\\*/gm, "\\*");
  //str = str.replace(/\\(\\)\]/gm, "\(\)]");
  //str = str.replace(/\\\\r\\\\n/g, "[\\\\s\\\\S]*");

  return str;
}

function ConvertNMAPMatching(line, counter){
  var bits = line.split(" ");
  if(bits[2][1] == "|"){
    var regBits = line.split("|");
    //console.log("Orig Regex:", regBits[1]);
    //var regex = convertNMAPRegexToJavascriptRegex(regBits[1]);
    var regex = "%"+convertNMAPRegexToJavascriptRegex(regBits[1])+"%ig";
    //console.log("Regex:", regex.trim());
    var CPERegex = new RegExp("(cpe:/.*?)$","g");
    var cpeLines = CPERegex.exec(line);
    var cpeArray = "";
    if(cpeLines && cpeLines.length > 1) cpeArray = cpeLines[1];
    var rkeys = [];
    try{
      var Regex = PCRE(regex, rkeys);
      nmapIdentification[counter] = {"new": regex.trim(), "orig": regBits[1], "cpes": cpeArray};
    } catch(err){
      //console.error("PCRE Regex Error:", regex);
      //console.error("PCRE Regex Error:", err);
    }

  }
  if(bits[2][1] == "="){

  }
}


function ConvertZtagMatching(line, counter){
  var bits = line.split("::DELIM::");
  if(bits.length > 1){
    var regex_tmp = bits[0].trim();
    var regex_go = regex_tmp.substring(1, regex_tmp.length-1);
    //console.log("Orig Regex:", regBits[1]);
    //var regex = convertNMAPRegexToJavascriptRegex(regBits[1]);
    var regex = "%"+convertNMAPRegexToJavascriptRegex(regex_go)+"%ig";
    //console.log("Regex:", regex.trim());
    var tag_temp = bits[1].trim();
    var tag_go = tag_temp.substring(1, tag_temp.length-1);
    var rkeys = [];

    try{
      var Regex = PCRE(regex, rkeys);
      ztagIdentification[counter] = {"new": regex.trim(), "tags": tag_go};
    } catch(err){
      console.error("ConvertZtagMatching PCRE Regex Error:", regex);
      console.error("ConvertZtagMatching PCRE Regex Error:", err);
    }

  }
}

function ConvertRecogMatching(line, counter){
  var bits = line.split("::DELIM::");
  if(bits.length > 1){
    var regex_tmp = bits[0].trim();
    var regex_go = regex_tmp.substring(1, regex_tmp.length-1);
    //console.log("Orig Regex:", regBits[1]);
    //var regex = convertNMAPRegexToJavascriptRegex(regBits[1]);
    var regex = "%"+convertNMAPRegexToJavascriptRegex(regex_go)+"%ig";
    //console.log("Regex:", regex.trim());
    var tag_temp = bits[1].trim();
    var tag_go = tag_temp.substring(1, tag_temp.length-1).replaceAll(" ", "_");
    var rkeys = [];

    try{
      var Regex = PCRE(regex, rkeys);
      recogIdentification[counter] = {"new": regex.trim(), "tags": tag_go};
    } catch(err){
      //console.error("ConvertRecogMatching PCRE Regex Error:", regex);
      //console.error("ConvertRecogMatching PCRE Regex Error:", err);
    }

  }
}

function LoadNMAPServiceProbes(){
  var lineReader = require('readline').createInterface({
    input: require('fs').createReadStream(base_path+ '/cpe-nmap-probes.txt')
  });
  var counter = 0;
  lineReader.on('line', function (line) {
    //console.log('Line from file:', line);
    //BannerToCPE(line.toLowerCase());
    ConvertNMAPMatching(line, counter);
    counter++;

    //process.exit()
  })
}

function LoadZtagRegex(){
  var lineReader = require('readline').createInterface({
    input: require('fs').createReadStream(base_path+ '/ztag_regexes.txt')
  });
  var counter = 0;
  lineReader.on('line', function (line) {
    //console.log('Line from file:', line);
    //BannerToCPE(line.toLowerCase());
    ConvertZtagMatching(line, counter);
    counter++;

    //process.exit()
  })
}

function LoadRecogRegex(){
  var lineReader = require('readline').createInterface({
    input: require('fs').createReadStream(base_path+ '/recog_regexes.txt')
  });
  var counter = 0;
  lineReader.on('line', function (line) {
    //console.log('Line from file:', line);
    //BannerToCPE(line.toLowerCase());
    ConvertRecogMatching(line, counter);
    counter++;

    //process.exit()
  })
}

function ProcessBanners(inputFile, results_write_stream){
  if(inputFile.indexOf('.gz') !== -1){
    var lineReader = require('readline').createInterface({
      input: fs.createReadStream(inputFile).pipe(zlib.createGunzip())
    });
  } else {
    var lineReader = require('readline').createInterface({
      input: require('fs').createReadStream(inputFile)

    });
  }

  var outline = "\""+ "BEST MATCH CPE MATCH" + "\",\"" + "PRODUCT NAME WEIGHT" + "\",\"" +
    "VERSION WEIGHT" +"\",\"" + "LEAF DISTANCE" + "\",\"" +
    "SUB LEAF DISTANCE"+"\",\""+"OTHER MATCH+\",\""+"NMAP MATCH"+"\",\""+"BANNER" +"\",\"" +
    "BANNER HASH"+"\", \""+"CPE HASH"+"\",\""+"SIM" +"\"";
  if(results_write_stream){
    WriteToStream(outline, results_write_stream);
  }

  console.log(outline);
  var isValidJSON = true;
  lineReader.on('line', function (line) {
    //console.log('Line from file:', line);
    var otherMatch = "";
    try {
      line = JSON.parse(line);
    } catch(error) {
      isValidJSON = false;
    }

    if(isValidJSON){
      if(line["_shodan"]){
        //Shodan line result
        if(line['data']){
          otherMatch = line['cpe'] ? "SHODAN:" + line['cpe']: "";
          line = line['data'];

        }
      } else {
        //Censys file
        line = line.banner;
      }
      if(line && typeof line == 'string' && line != ''){
        line = line.substring(0, 512);
        BannerToCPE(line.toLowerCase(), results_write_stream, otherMatch);
      }
    }

    //process.exit()
  })
}

function BannerToCPE(banner, results_write_stream, otherMatch){
  var bannerMatching = {banner: banner, best_match: "none"};
  var products = [];
  //var versionProspects = GetBannerVersionMatches(banner);
  var versionProspects = GetCPEVersionMatches(banner);
  //console.log(versionProspects);
  //tes = undefined;
  //console.log(tes[0]);
  /*
  if(versionProspects && versionProspects.length > 0){
    for(var i=0; i < versionProspects.length; i++){

      if(CPEVersionList[versionProspects[i]]){
        products.push(versionProspects[i]);
      }
      //bannerMatching[versionProspects[i]] = {};
    }
  }*/
  var uniq_regex = RegExp(/(\b\w\b)(?!.*\b\1\b)/gi);
  var regbits = uniq_regex.exec(banner);
  var banner_hash = "";
  if(regbits && regbits.length > 1) {banner_words = regbits.join(" ");banner_hash = ssdeep.digest(banner_words);}


  if(versionProspects && versionProspects.length > 0){
    //bannerMatching = BestMatchByProduct(versionProspects, {}, banner);
    //console.log(JSON.stringify(bannerMatching,  null, '\t'));
    var best_match = BestMatchByProduct(versionProspects, {}, banner, banner_hash);
    var nmapMatch = "";
    for(var prop in nmapIdentification){
      try{
        //console.log("Orig Regex:", nmapIdentification[prop]["orig"]);
        //console.log("Attempting Regex:", nmapIdentification[prop]["new"]);
        var Regex = PCRE(nmapIdentification[prop]["new"], "gi");

        while(thisMatch = Regex.exec(banner)){
          //console.log(thisMatch);
          nmapMatch += nmapIdentification[prop]["cpes"];
          if(thisMatch[1]) nmapMatch = nmapMatch.replace('$1', thisMatch[1]);
          if(thisMatch[2]) nmapMatch = nmapMatch.replace('$2', thisMatch[2]);
          if(thisMatch[3]) nmapMatch = nmapMatch.replace('$3', thisMatch[3]);
          if(thisMatch[4]) nmapMatch = nmapMatch.replace('$4', thisMatch[4]);
          if(thisMatch[5]) nmapMatch = nmapMatch.replace('$5', thisMatch[5]);
          if(thisMatch[6]) nmapMatch = nmapMatch.replace('$6', thisMatch[6]);
        }
      } catch(err){
        console.error("NMAP Regex Error:", err);
        console.error("Orig Regex:", nmapIdentification[prop]["orig"]);
        console.error("Attempting Regex:", nmapIdentification[prop]["new"]);
      }


    }
    var ztagMatch = "";
    for(var prop in ztagIdentification){
      try{
        //console.log("Orig Regex:", nmapIdentification[prop]["orig"]);
        //console.log("Attempting Regex:", nmapIdentification[prop]["new"]);
        var Regex = PCRE(ztagIdentification[prop]["new"], "gi");

        while(thisMatch = Regex.exec(banner)){
          //console.log(thisMatch);
          otherMatch += " ZTAG:" + ztagIdentification[prop]["tags"] + " ";
        }
      } catch(err){
        console.error("ZTAG Regex Error:", err);
        console.error("ZTAG Regex:", ztagIdentification[prop]["new"]);
      }


    }

    for(var prop in recogIdentification){
      try{
        //console.log("Orig Regex:", nmapIdentification[prop]["orig"]);
        //console.log("Attempting Regex:", nmapIdentification[prop]["new"]);
        var Regex = PCRE(recogIdentification[prop]["new"], "gi");

        while(thisMatch = Regex.exec(banner)){
          //console.log(thisMatch);
          otherMatch += " RECOG:" + recogIdentification[prop]["tags"] + " ";
        }
      } catch(err){
        console.error("Recog Regex Error:", err);
        console.error("Recog Regex:", recogIdentification[prop]["new"]);
      }


    }
    if(best_match['best_product_match'] || nmapMatch != ""){
      //console.log(best_match['banner_keys']);

      var best_cpe_hash = cpeHashes[best_match['best_product_match']];
      var cpe_banner_similarity = best_match['best_similarity'];// 75
      //var ztag_match = CheckZTag(bannerMatching.banner);
      //otherMatch += " " + ztag_match;
      //console.log(best_match['banner_keys']);
      var outline = "\""+ SafeEncode(best_match['best_product_match'])+ "\",\"" +SafeEncode(best_match['best_product_weight']) +"\",\""+
        SafeEncode(best_match['best_product_version_weight']) +"\",\""+ SafeEncode(best_match['best_product_leaf_diff'])+"\",\"" +
        SafeEncode(best_match['best_product_sub_leaf_diff'])+"\",\""+ SafeEncode(otherMatch)+"\",\""+ SafeEncode(nmapMatch)+"\",\"" +SafeEncode(bannerMatching.banner) +"\",\"" +
        SafeEncode(banner_hash) +"\",\""+ SafeEncode(best_cpe_hash)+"\",\"" + SafeEncode(cpe_banner_similarity)  +"\"";
      WriteToStream(outline, results_write_stream);

      console.log(outline);
    }
    /*
    for(var prop in bannerMatching){
      console.log("Prop: ", prop)
      if(bannerMatching[prop] && bannerMatching[prop]['best_product_match']){
        console.log("\""+ encodeURI(bannerMatching[prop]['best_product_match']), "\",\"",  encodeURI(bannerMatching[prop]['best_product_weight']) +"\",\"",
          encodeURI(bannerMatching[prop]['best_product_version_weight']) +"\",\"",  encodeURI(bannerMatching[prop]['best_product_leaf_diff'])+"\",\"",
          encodeURI(bannerMatching[prop]['best_product_sub_leaf_diff'])+"\",\"",bannerMatching.banner  +"\""
        );
      }
    } */
  }

}

String.prototype.replaceAll = function(search, replacement) {
    var target = this;
    return target.split(search).join(replacement);
};

function SafeEncode(line){
  if(line && typeof line == 'string'){
    line = line.replaceAll('"', '\\"');
    line = line.replaceAll(/(?:\r\n|\r|\n)/g, '\\r\\n');
  }

  return line;
}

function BestMatchByProduct(versionProspects, bannerMatching, banner, banner_hash){
  //console.log("Best Match By Product: ", versionProspects.length);
  var returnObject = {};
  returnObject['best_product_match'] = "";
  returnObject['best_product_weight'] = 0;
  returnObject['best_product_vendor_weight'] = 0;
  returnObject['best_product_version_weight'] = 0;
  returnObject['best_product_leaf_diff'] = 9999999;
  returnObject['best_product_sub_leaf_diff'] = 9999999;
  returnObject['banner_keys'] = "";
  returnObject['sim'] = "";
  var fullVersionArray = GetBannerVersionMatches(banner);
  for(var i=0; i < versionProspects.length; i++){
    var potential_cpes = CPEVersionList[versionProspects[i]];
    bannerMatching[versionProspects[i]] = {};
    if(potential_cpes){
      bannerMatching[versionProspects[i]]['product_cpe_weights'] = {};
      bannerMatching[versionProspects[i]]['best_product_match'] = "";
      bannerMatching[versionProspects[i]]['best_product_weight'] = 0;
      bannerMatching[versionProspects[i]]['best_product_leaf_diff'] = 9999999; //badmatch
      bannerMatching[versionProspects[i]]['best_product_sub_leaf_diff'] = 9999999; //badmatch
      bannerMatching[versionProspects[i]]['potential_cpes'] = potential_cpes;
      bannerMatching[versionProspects[i]]['banner_keys'] = "";
      for(var t=0; t < potential_cpes.length; t++){
        var weight = 0;
        var vendor_weight = 0;
        var sub_leaf_position = 0;
        var version_weight = 0;
        var sub_version_weight = 0;
        var cpe = potential_cpes[t];
        var sub_leaf_flag = false;


        /*

        */


        //console.log("This CPE: " , cpe);

        /*
        0    1    2                          3        4
        cpe:/a:mediahouse_software:statistics_server:4.28
        */
        var cpe_bits = cpe.split(":");
        var sub_leaf = "jabberjabberjabberwocky";
        /*
          var software = cpe_bits[3].replace("_", " ");
          if(banner.indexOf(software) > -1){
            weight = 1;
          }
        */
        var banner_keys = "";
        var banner_keys2 = "";
        var version = cpe_bits[4];
        if(cpe_bits[3].indexOf("_") > -1){
          var software_bits = cpe_bits[3].split("_");
          //console.log("CPE: " + cpe_bits[3]);
          var divider = 0;
          for(var g=0; g < software_bits.length; g++){
            var soft = software_bits[g].replace(/[^a-zA-Z0-9\-]/g, "");
            //console.log("match:", cpe_bits[3]);
            //console.log("match:", soft)
            var regexMatch = new RegExp("((_|-|\\b)"+soft+"(_|-|\\b))","g");
            if(soft.length > 1 && regexMatch.test(banner) && isNaN(soft)){
              //if(weight == 0){ weight = weight + 1000; }
              //console.log("Weight: ", soft,wordList[soft], software_bits.length);
              divider++
              weight += ((wordList[soft] ? wordList[soft] : 93.999));
              if(banner.indexOf(version) < banner.indexOf(soft)){
                weight -= 10;
              }
            } else {
              weight -= ((wordList[soft] ? ((wordList[soft]/10)) : 10));
              //divider--
            }
          }
          if(weight != 0){
            banner_keys = banner.replace(/\W+/g, " ").split(" ");
            banner_keys2 = [];
            for(var kid =0; kid < banner_keys.length; kid++){
              if(banner_keys[kid].length > 2 && isNaN(banner_keys[kid]) && cpe.indexOf(banner_keys[kid]) > -1){
                /*
                weight += ((wordList[banner_keys[kid]] ? ((wordList[banner_keys[kid]])) : 93.999));
                banner_keys2.push(banner_keys[kid] + "-"+ weight);
                divider++
                */

              }
            }
          }

          if(divider){
            weight = weight / divider;
          }
        } else {
          //var soft = cpe_bits[3].replace(/\W+/g, "");
          var soft = cpe_bits[3].replace(/[^a-zA-Z0-9\-\_\.]/g, "");
          var regexMatch = RegExp("((_|-|\\b)"+soft+"(_|-|\\b))","g");
          if(soft.length > 3 && regexMatch.test(banner) && isNaN(soft)){
            weight = (wordList[soft] ? wordList[soft] : 93.999);
            //console.log("Weight: ", soft,wordList[soft], software_bits.length);
          }

        }

        if(cpe_bits[2].indexOf("_") > -1){
          var vendor_bits = cpe_bits[2].split("_");
          for(var g=0; g < vendor_bits.length; g++){
            if(banner.indexOf(vendor_bits[g]) > -1){
              vendor_weight = 1000;
              var regexMatch = RegExp("((_|-|\\b)"+vendor_bits[g]+"(_|-|\\b))","g");
              if(vendor_bits[g].length > 3 && regexMatch.test(banner)  && weight > 0){
                weight = ((weight  + (wordList[vendor_bits[g]] ? wordList[vendor_bits[g]] : 93.999)) / 2);
                //console.log("Weight: ", soft,wordList[soft], software_bits.length);
              }
            }
          }
        } else {
          if(banner.indexOf(cpe_bits[2]) > -1){
            vendor_weight = 1000;
            var regexMatch = RegExp("((_|-|\\b)"+cpe_bits[2]+"(_|-|\\b))","g");
            if(cpe_bits[2].length > 3 && regexMatch.test(banner)  && weight > 0){
              weight = ((weight  +(wordList[cpe_bits[2]] ? wordList[cpe_bits[2]] : 93.999)) / 2);
              //console.log("Weight: ", soft,wordList[soft], software_bits.length);
            }
          }
        }
        var sim = 0;
        //sim = ssdeep.similarity(banner_hash, cpeHashes[cpe]);
        //weight = sim
        var version_leaf = version.substr(versionProspects[i].length);
        var version_position = banner.indexOf(versionProspects[i]);
        var leaf_position = banner.indexOf(version_leaf);
        if(leaf_position > -1 && leaf_position < 10 && weight > 0){
          version_weight = 1000;
          weight = weight +1;
        }
        var sub_leaf = "";
        if(cpe_bits[5] && cpe_bits[5] != ""){
          sub_leaf = cpe_bits[5];
          sub_leaf_position = banner.indexOf(sub_leaf);
          sub_leaf_flag = true;
        }
        //var sim = 0;
        //sim = ssdeep.similarity(banner_hash, cpeHashes[cpe]);
        //weight = sim
        if(weight > 0){
          weight = weight - 1;
          //sim = ssdeep.similarity(banner_hash, cpeHashes[cpe]);
          //weight += sim
          //sim = ssdeep.similarity(banner_hash, cpeHashes[cpe]);

          for(var gg = 0; gg < fullVersionArray.length; gg++){
            if(versionProspects[i] == fullVersionArray[gg]){
              weight = weight +2;
            }
          }
        }

        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe] = {};
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['cpe_name'] = cpe;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['leaf_position'] = leaf_position;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['sub_leaf_position'] = sub_leaf_position;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['sub_leaf_flag'] = sub_leaf_flag;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['version_position'] = version_position;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['weight'] = weight;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['version_weight'] = version_weight;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['vendor_weight'] = vendor_weight;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['banner_keys'] = banner_keys2;
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['sim'] = sim;

        var leaf_diff = (leaf_position - version_position) ;
        if (leaf_diff < 0){
          leaf_diff = 9999999; //bad match
        } else {
          //weight = weight + 1;
        }
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['leaf_diff'] = leaf_diff;
        var sub_leaf_diff = (sub_leaf_position - version_position) ;
        if (sub_leaf_diff < 0){
          sub_leaf_diff = 9999999; //bad match
        } else {
          //weight = weight + 1;
        }
        bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]['sub_leaf_diff'] = sub_leaf_diff;

        //console.log(cpe);
        //console.log(banner);
        //console.log(JSON.stringify(bannerMatching[versionProspects[i]]['product_cpe_weights'][cpe]));

      }
      //console.log(bannerMatching[versionProspects[i]]['product_cpe_weights']);
      var weight_object = bannerMatching[versionProspects[i]]['product_cpe_weights'];
      for(var cp in weight_object) {
        var weighted_cpe = weight_object[cp];
        //console.log("Checking weighted CPE: ", weighted_cpe['cpe_name'], weighted_cpe['weight']);
        //console.log("Best OS Weight: " +  bannerMatching[versionProspects[i]]['best_product_weight']);
        //console.log("CPE Weight: " + weighted_cpe.weight);
        var can_match = true;
        if(weighted_cpe.sub_leaf_flag && weighted_cpe.sub_leaf_diff == 9999999){
          can_match = true;
        }
        if(can_match && weighted_cpe.weight != 0 && (returnObject['best_product_weight'] <= weighted_cpe.weight || (
        returnObject['best_product_weight'] <= weighted_cpe.weight && weighted_cpe.leaf_diff <= returnObject['best_product_leaf_diff']
              && weighted_cpe.sub_leaf_diff <= returnObject['best_product_sub_leaf_diff'])
          )
          ){
          //console.log("In best match: ", weighted_cpe['cpe_name']); //
          /*
          bannerMatching[versionProspects[i]]['best_banner'] = banner;
          bannerMatching[versionProspects[i]]['best_product_match'] = weighted_cpe['cpe_name'];
          bannerMatching[versionProspects[i]]['best_product_weight'] = weighted_cpe['weight'];
          bannerMatching[versionProspects[i]]['best_product_vendor_weight'] = weighted_cpe['vendor_weight'];
          bannerMatching[versionProspects[i]]['best_product_version_weight'] = weighted_cpe['version_weight'];
          bannerMatching[versionProspects[i]]['best_product_leaf_diff'] = weighted_cpe['leaf_diff'];
          bannerMatching[versionProspects[i]]['best_product_sub_leaf_diff'] = weighted_cpe['sub_leaf_diff'];
          */
          returnObject['best_banner'] = banner;
          returnObject['best_product_match'] = weighted_cpe['cpe_name'];
          returnObject['best_product_weight'] = weighted_cpe['weight'];
          returnObject['best_product_vendor_weight'] = weighted_cpe['vendor_weight'];
          returnObject['best_product_version_weight'] = weighted_cpe['version_weight'];
          returnObject['best_product_leaf_diff'] = weighted_cpe['leaf_diff'];
          returnObject['best_product_sub_leaf_diff'] = weighted_cpe['sub_leaf_diff'];
          returnObject['banner_keys']  = weighted_cpe['banner_keys'];
          returnObject['best_similarity']  = weighted_cpe['sim'];
        } else {
          //console.log("No match?");  //
        }

      }
      //delete bannerMatching[versionProspects[i]]['potential_cpes'];
    }
  }
  return returnObject;
}


var wordList = {}
var topWord = false;
var mostUsedFrequency = 0;

function ConvertCPEToArray(name){
  var cpe = name;
  /*
  if(cpe.indexOf("x28") > -1 && cpe.indexOf("x29") > -1) {
    //console.log("replace hex");
    cpe = cpe.replace("x28", "(").replace("x29", ")");
  }*/

  /*
  0    1    2                          3        4
  cpe:/a:mediahouse_software:statistics_server:4.28
  */
  return cpe.split(":");
}

var CPEVersionList = {};
LoadNMAPServiceProbes();
LoadZtagRegex();
LoadRecogRegex();

var cpeReader = require('readline').createInterface({
 input: require('fs').createReadStream(base_path+ '/uniq-cpes.txt')
});
cpeReader.on('line', function (line) {
   var cpeName = line;
   var cpeBits = ConvertCPEToArray(cpeName);
   var version = GetCPEVersionMatches(cpeBits[4]);
   /*
   if(!CPEVersionList[version]){
     CPEVersionList[version] = [];
   }
   */
   if(cpeBits[3]){
     var temp = cpeBits[3].split("_");
     //if(temp.constructor === Array) cpeBits[3] = temp.join(" ");
     //cpeHashes[cpeName] = ssdeep.digest(cpeBits[3]);

     cpeHashes[cpeName] = ssdeep.digest((Array.isArray(cpeBits[3]) ? cpeBits[3].join(" ") : cpeBits[3]) +
      (Array.isArray(cpeBits[4]) ? cpeBits[4].join(" ") : cpeBits[4]) +
      (Array.isArray(cpeBits[5]) ? cpeBits[5].join(" ") : cpeBits[5]));

     //console.log(versionProspects);
     if(cpeBits[1] == "/a" || cpeBits[1] == "/o"){
       if(version.length > 1){
         for(var i=0; i< version.length; i++){
           if(!CPEVersionList[version[i]]){
             CPEVersionList[version[i]] = [];
           }
           //console.log("Loading:", cpeName, version[i]);
           CPEVersionList[version[i]].push(cpeName);
         }
       } else {
         if(!CPEVersionList[version[0]]){
           CPEVersionList[version[0]] = [];
         }
         CPEVersionList[version[0]].push(cpeName);
       }
       //CPEVersionList[version].push(cpeName);

     }
   }

 }).on('close', function() {
   var frequencyReader = require('readline').createInterface({
     input: require('fs').createReadStream('./word-frequency.txt')
   });
   //console.log("Loading Word Frequency List");
   frequencyReader.on('line', function (line) {

     //console.log('Line from file:', line);
     var bits = line.toLowerCase().split(" ");
     if(!topWord){
       mostUsedFrequency = bits[1];
       topWord = true;
     }
     var wordWeight = ((bits[1] / mostUsedFrequency) * 100 +1);
     //console.log("WordWeight: " , wordWeight, bits[1], mostUsedFrequency)
     wordList[bits[0]] = 95 - wordWeight;
     //StartWithBanner(line.toLowerCase());
     //process.exit()
   }).on('close', function() {
     //LoadNMAPServiceProbes();
     Main();

     //console.log(JSON.stringify(CPEVersionList['1.3.4']))
   });
 });
