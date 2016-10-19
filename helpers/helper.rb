require 'rubygems'

# The helper class exists to do string manipulation and heavy lifting
class Float
  def ceil2(exp = 0)
   multiplier = 10 ** exp
   ((self * multiplier).ceil).to_f/multiplier.to_f
  end
end

def url_escape_hash(hash)
	hash.each do |k,v|
		v = CGI::escapeHTML(v)

    if v
			# convert bullets
			v = v.gsub("*-","<bullet>")
			v = v.gsub("-*","</bullet>")

			#convert h4
			v = v.gsub("[==","<h4>")
			v = v.gsub("==]","</h4>")

      		#convert indent text
			v = v.gsub("[--","<indented>")
			v = v.gsub("--]","</indented>")

			#convert indent text
			v = v.gsub("[~~","<italics>")
			v = v.gsub("~~]","</italics>")
    end

		# replace linebreaks with paragraph xml elements
		if v =~ /\r\n/
			new_v = ""
			brs = v.split("\r\n")
			brs.each do |br|
				new_v << "<paragraph>"
				new_v << br
				new_v << "</paragraph>"
			end

			v = new_v
		elsif k == "remediation" or k == "overview" or k == "poc" or k == "affected_hosts"
			new_v = "<paragraph>#{v}</paragraph>"
			v = new_v
		end

		hash[k] = v
	end

	return hash
end

def meta_markup(text)
	new_text = text.gsub("<paragraph>","&#x000A;").gsub("</paragraph>","")
	new_text = new_text.gsub("<bullet>","*-").gsub("</bullet>","-*")
	new_text = new_text.gsub("<h4>","[==").gsub("</h4>","==]")
	new_text = new_text.gsub("<code>","[[[").gsub("</code>","]]]")
	new_text = new_text.gsub("<indented>","[--").gsub("</indented>","--]")
	new_text = new_text.gsub("<italics>","[~~").gsub("</italics>","~~]")
end


# URL escaping messes up the inserted XML, this method switches it back to XML elements

def meta_markup_unencode(findings_xml, customer_name)

  # code tags get added in later
	findings_xml = findings_xml.gsub("[[[","<code>")
	findings_xml = findings_xml.gsub("]]]","</code>")

	# creates paragraphs
	findings_xml = findings_xml.gsub("&lt;paragraph&gt;","<paragraph>")
	findings_xml = findings_xml.gsub("&lt;/paragraph&gt;","</paragraph>")
	# same for the bullets
	findings_xml = findings_xml.gsub("&lt;bullet&gt;","<bullet>")
	findings_xml = findings_xml.gsub("&lt;/bullet&gt;","</bullet>")
	# same for the h4
	findings_xml = findings_xml.gsub("&lt;h4&gt;","<h4>")
	findings_xml = findings_xml.gsub("&lt;/h4&gt;","</h4>")
	# same for the code markings
	findings_xml = findings_xml.gsub("&lt;code&gt;","<code>")
	findings_xml = findings_xml.gsub("&lt;/code&gt;","</code>")
	# same for the indented text
	findings_xml = findings_xml.gsub("&lt;indented&gt;","<indented>")
	findings_xml = findings_xml.gsub("&lt;/indented&gt;","</indented>")
	# same for the indented text
	findings_xml = findings_xml.gsub("&lt;italics&gt;","<italics>")
	findings_xml = findings_xml.gsub("&lt;/italics&gt;","</italics>")

  # changes the <<CUSTOMER>> marks
  if customer_name
	  findings_xml = findings_xml.gsub("&amp;lt;&amp;lt;CUSTOMER&amp;gt;&amp;gt;","#{customer_name}")
  end

  #this is for re-upping the comment fields
  findings_xml = findings_xml.gsub("&lt;modified&gt;","<modified>")
  findings_xml = findings_xml.gsub("&lt;/modified&gt;","</modified>")

  findings_xml = findings_xml.gsub("&lt;new_finding&gt;","<new_finding>")
  findings_xml = findings_xml.gsub("&lt;/new_finding&gt;","</new_finding>")

  # these are for beautification
  findings_xml = findings_xml.gsub("&amp;quot;","\"")
  findings_xml = findings_xml.gsub("&amp;","&")
  findings_xml = findings_xml.gsub("&amp;lt;","&lt;").gsub("&amp;gt;","&gt;")

  return findings_xml
end

def compare_text(new_text, orig_text)
 if orig_text == nil
    # there is no master finding, must be new
    t = ""
    t << "<new_finding></new_finding>#{new_text}"
    return t
  end

  if new_text == orig_text
    return new_text
  else
    n_t = ""

    n_t << "<modified></modified>#{new_text}"
    return n_t
  end
end

# CVSS helper, there is a lot of hardcoded stuff
def cvss(data)
	av = data["av2"]
	ac = data["ac2"]
	au = data["au2"]
	c = data["c2"]
	i = data["i2"]
	a = data["a2"]
	e = data["e2"]
	rl = data["rl2"]
	rc = data["rc2"]
	cdp = data["cdp"]
	td = data["td"]
	cr = data["cr2"]
	ir = data["ir2"]
	ar = data["ar2"]

	if ac == "High"
	    cvss_ac = 0.35
	elsif ac == "Medium"
	    cvss_ac = 0.61
	else
	    cvss_ac = 0.71
	end

	if au == "None"
	    cvss_au = 0.704
	elsif au == "Single"
	    cvss_au = 0.56
	else
	    cvss_au = 0.45
	end

	if av == "Local"
	    cvss_av = 0.395
	elsif av == "Local Network"
	    cvss_av = 0.646
	else
	    cvss_av = 1
	end

	if c == "None"
	    cvss_c = 0
	elsif c == "Partial"
	    cvss_c = 0.275
	else
	    cvss_c = 0.660
	end

	if i == "None"
	    cvss_i = 00
	elsif i == "Partial"
	    cvss_i = 0.275
	else
	    cvss_i = 0.660
	end

	if a == "None"
	    cvss_a = 0
	elsif a == "Partial"
	    cvss_a = 0.275
	else
	    cvss_a = 0.660
	end


	# temporal score calculations
	if e == "Unproven Exploit Exists"
	    cvss_e = 0.85
	elsif e == "Proof-of-Concept Code"
	    cvss_e = 0.90
	elsif e == "Functional Exploit Exists"
	    cvss_e = 0.95
	else
	    cvss_e = 1
	end

	if rl == "Official Fix"
	    cvss_rl = 0.87
	elsif rl == "Temporary Fix"
	    cvss_rl = 0.90
	elsif rl == "Workaround"
	    cvss_rl = 0.95
	else
	    cvss_rl = 1
	end

	if rc == "Unconfirmed"
	    cvss_rc = 0.90
	elsif rc == "Uncorroborated"
	    cvss_rc = 0.95
	else
	    cvss_rc = 1
	end


	#environemental
	if cdp == "Low"
	    cvss_cdp = 0.1
	elsif cdp == "Low-Medium"
	    cvss_cdp = 0.3
	elsif cdp == "Medium-High"
	    cvss_cdp = 0.4
	elsif cdp == "High"
	    cvss_cdp = 0.5
	else
	    cvss_cdp = 0
	end

	if td == "None"
	    cvss_td = 0
	elsif td == "Low"
	    cvss_td = 0.25
	elsif td == "Medium"
	    cvss_td = 0.75
	else
	    cvss_td = 1
	end

	if cr == "Low"
	    cvss_cr = 0.5
	elsif cr == "High"
	    cvss_cr = 1.51
	else
	    cvss_cr = 1
	end

	if ir == "Low"
	    cvss_ir = 0.5
	elsif ir == "High"
	    cvss_ir = 1.51
	else
	    cvss_ir = 1
	end

	if ar == "Low"
	    cvss_ar = 0.5
	elsif ar == "High"
	    cvss_ar = 1.51
	else
	    cvss_ar = 1
	end


	cvss_impact = 10.41 * (1 - (1 - cvss_c) * (1 - cvss_i) * (1 - cvss_a))
	cvss_exploitability = 20 * cvss_ac * cvss_au * cvss_av
	if cvss_impact == 0
	    cvss_impact_f = 0
	else
	    cvss_impact_f = 1.176
	end
	cvss_base = (0.6*cvss_impact + 0.4*cvss_exploitability-1.5)*cvss_impact_f

	cvss_temporal = cvss_base * cvss_e * cvss_rl * cvss_rc

	cvss_modified_impact = [10, 10.41 * (1 - (1 - cvss_c * cvss_cr) * (1 - cvss_i * cvss_ir) * (1 - cvss_a * cvss_ar))].min

	if cvss_modified_impact == 0
	    cvss_modified_impact_f = 0
	else
	    cvss_modified_impact_f = 1.176
	end

	cvss_modified_base = (0.6*cvss_modified_impact + 0.4*cvss_exploitability-1.5)*cvss_modified_impact_f
	cvss_adjusted_temporal = cvss_modified_base * cvss_e * cvss_rl * cvss_rc
	cvss_environmental = (cvss_adjusted_temporal + (10 - cvss_adjusted_temporal) * cvss_cdp) * cvss_td

	if cvss_environmental
	    cvss_total = cvss_environmental
	elsif cvss_temporal
	    cvss_total = cvss_temporal
	else
	    cvss_total = cvss_base
	end

#if cvss_total == 0
#data["risk_cvss_v2"]=0
##data["risk"]=0

#elsif (cvss_total >= 0.1 and cvss_total <= 3.9)
#data["risk_cvss_v2"]=1
#data["risk"]=1

#elsif (cvss_total >= 4.0 and cvss_total <= 6.9)
#data["risk_cvss_v2"]=2
#data["risk"]=2

#elsif (cvss_total >= 7.0 and cvss_total <= 8.9)
#data["risk_cvss_v2"]=3
#data["risk"]=3

#else
#data["risk_cvss_v2"]=4
#data["risk"]=4
#end

  data["risk_cvss_v2"]=data["risk"]

	data["cvss_base2"] = sprintf("%0.1f" % cvss_base)
	data["cvss_impact2"] = sprintf("%0.1f" % cvss_impact)
	data["cvss_exploitability2"] = sprintf("%0.1f" % cvss_exploitability)
	data["cvss_temporal2"] = sprintf("%0.1f" % cvss_temporal)
	data["cvss_environmental2"] = sprintf("%0.1f" % cvss_environmental)
	data["cvss_modified_impact2"] = sprintf("%0.1f" % cvss_modified_impact)
	data["cvss_total2"] = sprintf("%0.1f" % cvss_total)

	return data
end

# there are three scoring types; risk, dread and cvss
#    this sets a score for all three in case the user switches later

# < hadhemi
def cvss3(data)
	av = data["av"]
	ac = data["ac"]
	pr = data["pr"]
	ui = data["ui"]
	c = data["c"]
	i = data["i"]
	a = data["a"]
	s = data["s"]
	e = data["e"]
	rl = data["rl"]
	rc = data["rc"]
	#CVSS3
	mav = data["mav"]
	mac = data["mac"]
	mpr = data["mpr"]
	mui = data["mui"]
	ms = data["ms"]
	mc = data["mc"]
	mi = data["mi"]
	ma = data["ma"]
	cr = data["cr"]
	ir = data["ir"]
	ar = data["ar"]


  if av == "Local"
	    cvss_av = 0.55
	elsif av == "Adjacent Network"
	    cvss_av = 0.62
	elsif av == "Network"
	    cvss_av = 0.85
	elsif av == "Physical"
	    cvss_av = 0.2
	end

	if ac == "High"
	    cvss_ac = 0.44
	elsif ac == "Low"
	    cvss_ac = 0.77
	end

	if pr == "None"
	    cvss_pr = 0.85
	elsif pr == "Low" and s == "Unchanged"
	    cvss_pr = 0.62
  elsif pr == "Low" and s == "Changed"
	    cvss_pr = 0.68
	elsif pr == "High" and s == "Unchanged"
	    cvss_pr = 0.27
  elsif pr == "High" and s == "Changed"
	    cvss_pr = 0.5
	end

	if ui == "None"
	    cvss_ui = 0.85
	elsif ui == "Required"
	    cvss_ui = 0.62
	end

	if c == "None"
	    cvss_c = 0
	elsif c == "Low"
	    cvss_c = 0.22
	elsif c == "High"
	    cvss_c = 0.56
	end

	if i == "None"
	    cvss_i = 0
	elsif i == "Low"
	    cvss_i = 0.22
	elsif i == "High"
	    cvss_i = 0.56
	end

	if a == "None"
	    cvss_a = 0
	elsif a == "Low"
	    cvss_a = 0.22
	elsif a == "High"
	    cvss_a = 0.56
	end


	# temporal score calculations
	if e == "Unproven Exploit Exists"
	    cvss_e = 0.91
	elsif e == "Proof-of-Concept Code"
	    cvss_e = 0.94
	elsif e == "Functional Exploit Exists"
	    cvss_e = 0.97
	else
	    cvss_e = 1
	end

	if rl == "Official Fix"
	    cvss_rl = 0.95
	elsif rl == "Temporary Fix"
	    cvss_rl = 0.96
	elsif rl == "Workaround"
	    cvss_rl = 0.97
	else
	    cvss_rl = 1
	end

	if rc == "Unknown"
	    cvss_rc = 0.92
	elsif rc == "Reasonable"
	    cvss_rc = 0.96
	else
	    cvss_rc = 1
	end


	#environemental

	if ms == "Not Defined"
		  ms = s
	end

	if mav == "Local"
	    cvss_mav = 0.55
	elsif mav == "Adjacent Network"
	    cvss_mav = 0.62
	elsif mav == "Network"
	    cvss_mav = 0.85
	elsif mav == "Physical"
	    cvss_mav = 0.2
	elsif mav == "Not Defined"
			cvss_mav = cvss_av
	end

	if mac == "High"
	    cvss_mac = 0.44
  elsif mac == "Low"
			cvss_mac = 0.77
	elsif mac == "Not Defined"
	    cvss_mac = cvss_ac
	end

	if mpr == "None"
	    cvss_mpr = 0.85
	elsif mpr == "Low" and ms == "Unchanged"
	    cvss_mpr = 0.62
  elsif mpr == "Low" and ms == "Changed"
	    cvss_mpr = 0.68
	elsif mpr == "High" and ms == "Unchanged"
	    cvss_mpr = 0.27
  elsif mpr == "High" and ms == "Changed"
	    cvss_mpr = 0.5
	elsif mpr == "Not Defined"
		cvss_mpr = cvss_pr
	end

	if mui == "None"
	    cvss_mui = 0.85
  elsif mui == "Required"
		  cvss_mui = 0.62
	elsif mui == "Not Defined"
	    cvss_mui = cvss_ui
	end


	if mc == "None"
	    cvss_mc = 0
	elsif mc == "Low"
	    cvss_mc = 0.22
	elsif mc == "Low"
		  cvss_mc = 0.56
	elsif mc == "Not Defined"
	    cvss_mc = cvss_c
	end

	if mi == "None"
	    cvss_mi = 00
	elsif mi == "Low"
	    cvss_mi = 0.22
	elsif mi == "High"
		  cvss_mi = 0.56
	elsif mi == "Not Defined"
	    cvss_mi = cvss_i
	end

	if ma == "None"
	    cvss_ma = 0
	elsif ma == "Low"
	    cvss_ma = 0.22
	elsif ma == "High"
			cvss_ma = 0.56
	elsif ma == "Not Defined"
	    cvss_ma = cvss_a
	end



	if cr == "Low"
	    cvss_cr = 0.5
	elsif cr == "High"
	    cvss_cr = 1.50
	else
	    cvss_cr = 1
	end

	if ir == "Low"
	    cvss_ir = 0.5
	elsif ir == "High"
	    cvss_ir = 1.50
	else
	    cvss_ir = 1
	end

	if ar == "Low"
	    cvss_ar = 0.5
	elsif ar == "High"
	    cvss_ar = 1.50
	else
	    cvss_ar = 1
	end

	# Score de Base
	cvss_impact_base = (1 - (1 - cvss_c) * (1 - cvss_i) * (1 - cvss_a))
	cvss_exploitability = 8.22 * cvss_ac * cvss_pr * cvss_av * cvss_ui
	# ici voir si la puissance 15 est correcte
	if s == "Unchanged"
		cvss_impact = 6.42 * cvss_impact_base
	else
		cvss_impact = 7.52 * (cvss_impact_base - 0.029) - 3.25 * ((cvss_impact_base - 0.02)**15)
	end

	if cvss_impact <= 0
	    cvss_base = 0.0
	elsif s == "Unchanged"
			#la fonction ceil2 = RoundUp
	    cvss_base = ([(cvss_impact + cvss_exploitability),10].min).ceil2(1)
	elsif s == "Changed"
	    cvss_base = ([(1.08*(cvss_impact + cvss_exploitability)),10].min).ceil2(1)
	end

	# Score temporel
	cvss_temporal = (cvss_base * cvss_e * cvss_rl * cvss_rc).ceil2(1)

	#Score enviromental
	cvss_impact_modified = [(1 - (1 - cvss_mc*cvss_cr) * (1 - cvss_mi*cvss_ir) * (1 - cvss_ma*cvss_ar)),0.915].min
	cvss_modified_exploitability = 8.22 * cvss_mac * cvss_mpr * cvss_mav * cvss_mui

	if ms == "Unchanged"
		cvss_modified_impact = 6.42 * cvss_impact_modified
	elsif ms == "Changed"
		cvss_modified_impact = 7.52 * (cvss_impact_modified - 0.029) - 3.25 * ((cvss_impact_modified - 0.02)**15)
	end


	if cvss_modified_impact <= 0
	    cvss_environmental = 0.0
	elsif ms == "Changed"
	    cvss_environmental = (([1.08*(cvss_modified_impact + cvss_modified_exploitability),10].min).ceil2(1) * cvss_rl * cvss_rc * cvss_e).ceil2(1)
	elsif ms == "Unchanged"
	    cvss_environmental = (([(cvss_modified_impact + cvss_modified_exploitability),10].min).ceil2(1) * cvss_rl * cvss_rc * cvss_e).ceil2(1)
	end

	#choix du score total
	if cvss_environmental
	    cvss_total = cvss_environmental
	elsif cvss_temporal
	    cvss_total = cvss_temporal
	else
	    cvss_total = cvss_base
	end

  if cvss_total == 0
  data["risk_cvss_v3"]=0
  #data["risk"]=0

  elsif (cvss_total >= 0.1 and cvss_total <= 3.9)
  data["risk_cvss_v3"]=1
  #data["risk"]=1

  elsif (cvss_total >= 4.0 and cvss_total <= 6.9)
  data["risk_cvss_v3"]=2
  #data["risk"]=2

  elsif (cvss_total >= 7.0 and cvss_total <= 8.9)
  data["risk_cvss_v3"]=3
  #data["risk"]=3

  else
  data["risk_cvss_v3"]=4
  #data["risk"]=4
  end

	data["cvss_base"] = sprintf("%0.1f" % cvss_base)
	#data["cvss_base"] = sprintf("%0.3f" % cvss_base)
	data["cvss_impact"] = sprintf("%0.1f" % cvss_impact)
	data["cvss_exploitability"] = sprintf("%0.1f" % cvss_exploitability)
	data["cvss_temporal"] = sprintf("%0.1f" % cvss_temporal)
	data["cvss_environmental"] = sprintf("%0.1f" % cvss_environmental)
	data["cvss_modified_impact"] = sprintf("%0.1f" % cvss_modified_impact)
	data["cvss_total"] = sprintf("%0.1f" % cvss_total)

	return data
end
# > hadhemi
def convert_score(finding)
	if(finding.cvss_total == nil)
		puts "|!| No CVSS score exists"
		finding.cvss_total = 0
	end
	if(finding.dread_total == nil)
		puts "|!| No CVSS score exists"
		finding.dread_total = 0
	end
	if(finding.risk == nil)
		puts "|!| No CVSS score exists"
		finding.risk = 0
	end
	return finding
end
