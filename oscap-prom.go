package main

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/araddon/dateparse"
	"github.com/pschou/go-sorting/numstr"
	"github.com/pschou/go-xmltree"
)

var version string

func main() {
	if len(os.Args) < 2 {
		os.Exit(0)
	}
	if os.Args[1] == "-h" || os.Args[1] == "-v" {
		fmt.Println("Version: " + version)
		os.Exit(0)
	}
	for _, file := range os.Args[1:] {
		parse(file)
	}
}

type ovalDef struct {
	title,
	ident,
	severity string
	result bool
}

func parse(file string) {
	dn, fn := path.Split(file)
	//fmt.Println("opening ", file)
	infile, err := os.Open(file)
	if err != nil {
		log.Println(err)
		return
	}
	defer infile.Close()
	tmpname := path.Join(dn, "."+fn)
	outfile, err := os.Create(tmpname)
	defer func() {
		if outfile != nil {
			outfile.Close()
			os.Remove(tmpname)
		}
	}()

	var buf bytes.Buffer
	buf.ReadFrom(infile)
	infile.Close()

	root, err := xmltree.Parse(buf.Bytes())
	if err != nil {
		log.Fatal(err)
	}

	/*
	   <oval_results xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5" xmlns="http://oval.mitre.org/XMLSchema/oval-results-5" xsi:schemaLocation="http://oval.mitre.org/XMLSchema/oval-results-5 oval-results-schema.xsd http://oval.mitre.org/XMLSchema/oval-common-5 oval-common-schema.xsd">
	     <generator>
	       <oval:product_name>cpe:/a:open-scap:oscap</oval:product_name>
	       <oval:product_version>1.2.17</oval:product_version>
	       <oval:schema_version>5.10</oval:schema_version>
	       <oval:timestamp>2023-03-28T14:36:21</oval:timestamp>
	*/

	{
		genTime, err := dateparse.ParseStrict(
			root.MatchOne(&xmltree.Selector{Label: "generator"}).
				MatchOne(&xmltree.Selector{Label: "timestamp"}).GetContent())
		if err == nil {
			dateVal := genTime.UnixMilli()
			fmt.Printf("node_cesa_scan_time %d\n", dateVal)
		}
	}
	{
		genTime, err := dateparse.ParseStrict(
			root.MatchOne(&xmltree.Selector{Label: "oval_definitions"}).
				MatchOne(&xmltree.Selector{Label: "generator"}).
				MatchOne(&xmltree.Selector{Label: "timestamp"}).GetContent())
		if err == nil {
			dateVal := genTime.UnixMilli()
			fmt.Printf("node_cesa_oval_time %d\n", dateVal)
		}
	}

	defToElm := make(map[string]ovalDef)

	/*
	   <definitions>
	       <definition id="oval:com.redhat.rhsa:def:20231335" version="637" class="patch">
	         <metadata>
	           <title>CESA-2023:1335: openssl security update (Important)</title>
	           <affected family="unix">
	             <platform>Red Hat Enterprise Linux 7</platform>
	           </affected>
	           <reference source="RHSA" ref_id="RHSA-2023:1335" ref_url="https://access.redhat.com/errata/RHSA-2023:1335"/>
	           <reference source="CVE" ref_id="CVE-2023-0286" ref_url="https://access.redhat.com/security/cve/CVE-2023-0286"/>
	*/

	for _, def := range root.MatchOne(&xmltree.Selector{Label: "oval_definitions"}).
		MatchOne(&xmltree.Selector{Label: "definitions"}).
		Match(&xmltree.Selector{Label: "definition"}) {
		if id := def.Attr("", "id"); id != "" {
			md := def.MatchOne(&xmltree.Selector{Label: "metadata"})
			od := ovalDef{
				title:    md.MatchOne(&xmltree.Selector{Label: "title"}).GetContent(),
				severity: md.FindOne(&xmltree.Selector{Label: "severity"}).GetContent(),
			}

			od.title = strings.TrimSpace(strings.TrimSuffix(od.title, "("+od.severity+")"))

			var list []string
			for _, ref := range md.Match(&xmltree.Selector{Label: "reference"}) {
				if src := ref.Attr("", "source"); src == "CVE" {
					list = append(list, ref.Attr("", "ref_id"))
				}
			}
			od.ident = strings.Join(list, ",")
			defToElm[id] = od
		}
	}

	/*
	   <results>
	      <system>
	        <definitions>
	          <definition definition_id="oval:com.redhat.rhsa:def:20231335" result="true" version="637">
	*/
	var ids []string
	for _, def := range root.MatchOne(&xmltree.Selector{Label: "results"}).
		MatchOne(&xmltree.Selector{Label: "system"}).
		MatchOne(&xmltree.Selector{Label: "definitions"}).
		Match(&xmltree.Selector{Label: "definition"}) {

		id := def.Attr("", "definition_id")
		result := def.Attr("", "result")
		if elm, ok := defToElm[id]; ok {
			elm.result = result == "true"
			defToElm[id] = elm
			ids = append(ids, id)
		}
	}

	sort.Slice(ids, func(i, j int) bool {
		return numstr.LessThanFold(ids[i], ids[j])
	})
	for _, id := range ids {
		elm := defToElm[id]
		var v int
		if elm.result {
			switch strings.ToLower(elm.severity) {
			case "low":
				v = 1
			case "moderate":
				v = 2
			case "important":
				v = 3
			case "critical":
				v = 4
			}
		}
		elm.title = strings.TrimPrefix(elm.title, "Unaffected components for: ")
		fmt.Printf("node_cesa_scan_results{title=%q,severity=%q,ident=%q} %d\n", elm.title, elm.severity, elm.ident, v)
	}
}
