require 'rubygems'
require 'nokogiri'
require 'zipruby'
require './model/master'

# For now, we need this to clean up import text a bit
def clean(text)
    return unless text

    text = text.squeeze(" ")
    text = text.gsub("<br>", "\n")
    text = text.gsub("<p>", "\n")
    text = text.gsub("<description>","")
    text = text.gsub("</description>","")
    text = text.gsub("<Score>","")
    text = text.gsub("</Score>","")
    #cvss
    text = text.gsub("<AV>","")
    text = text.gsub("</AV>","")
    text = text.gsub("<Au>","")
    text = text.gsub("</Au>","")
    text = text.gsub("<AC>","")
    text = text.gsub("</AC>","")
    text = text.gsub("<PR>","")
    text = text.gsub("</PR>","")
    text = text.gsub("<UI>","")
    text = text.gsub("</UI>","")
    text = text.gsub("<S>","")
    text = text.gsub("</S>","")
    text = text.gsub("<C>","")
    text = text.gsub("</C>","")
    text = text.gsub("<I>","")
    text = text.gsub("</I>","")
    text = text.gsub("<A>","")
    text = text.gsub("</A>","")

    text = text.gsub("<E>","")
    text = text.gsub("</E>","")
    text = text.gsub("<RL>","")
    text = text.gsub("</RL>","")
    text = text.gsub("<RC>","")
    text = text.gsub("</RC>","")

    text = text.gsub("<CDP>","")
    text = text.gsub("</CDP>","")
    text = text.gsub("<TD>","")
    text = text.gsub("</TD>","")

    text = text.gsub("<MAV>","")
    text = text.gsub("</MAV>","")
    text = text.gsub("<MAC>","")
    text = text.gsub("</MAC>","")
    text = text.gsub("<MPR>","")
    text = text.gsub("</MPR>","")
    text = text.gsub("<MUI>","")
    text = text.gsub("</MUI>","")
    text = text.gsub("<MS>","")
    text = text.gsub("</MS>","")
    text = text.gsub("<MC>","")
    text = text.gsub("</MC>","")
    text = text.gsub("<MI>","")
    text = text.gsub("</MI>","")
    text = text.gsub("<MA>","")
    text = text.gsub("</MA>","")
    text = text.gsub("<CR>","")
    text = text.gsub("</CR>","")
    text = text.gsub("<IR>","")
    text = text.gsub("</IR>","")
    text = text.gsub("<AR>","")
    text = text.gsub("</AR>","")

    #nessus
    text = text.gsub("<cvss_base_score>","")
    text = text.gsub("</cvss_base_score>","")
    #cvss

    text = text.gsub("<solution>","")
    text = text.gsub("</solution>","")
    text = text.gsub("<see_also>","")
    text = text.gsub("</see_also>","")
    text = text.gsub("<plugin_output>\n\n","")    #remove leading newline characters from nessus plugin output too!
    text = text.gsub("<plugin_output>\n","")    #remove leading newline character from nessus plugin output too!
    text = text.gsub("<plugin_output>","")
    text = text.gsub("</plugin_output>","")

    # burp stores html and needs to be removed, TODO better way to handle this
    text = text.gsub("</p>", "")
    text = text.gsub("<li>", "\n")
    text = text.gsub("</li>", "")
    text = text.gsub("<ul>", "\n")
    text = text.gsub("</ul>", "")
    text = text.gsub("<table>", "")
    text = text.gsub("</table>", "")
    text = text.gsub("<td>", "\n")
    text = text.gsub("</td>", "")
    text = text.gsub("<tr>", "")
    text = text.gsub("</tr>", "")
    text = text.gsub("<b>", "")
    text = text.gsub("</b>", "")
    text = text.gsub("<![CDATA[","")
    text = text.gsub("]]>","")
    text = text.gsub("\n\n","\n")

    text = text.gsub("\n","\r\n")

    text_ = url_escape_hash({'a' => text})
    text = text_['a']

    return text
end

def uniq_findings(findings)
    vfindings = []
    # this gets a uniq on the findings and groups hosts, could be more efficient
    findings.each do |single|
        # check if the finding has been added before
        exists = vfindings.detect {|f| f["title"] == single.title }

        if exists
            #get the index
            i = vfindings.index(exists)
            exists.affected_hosts = clean(exists.affected_hosts+", #{single.affected_hosts}")
            if exists.notes
                exists.notes = exists.notes+"<paragraph></paragraph><paragraph></paragraph>#{single.notes}"
            end
            vfindings[i] = exists
        else
            vfindings << single
        end
    end
    return vfindings
end

def parse_nessus_xml(xml)
    vulns = Hash.new
    findings = Array.new
    items = Array.new

    doc = Nokogiri::XML(xml)

    doc.css("//ReportHost").each do |hostnode|
        if (hostnode["name"] != nil)
            host = hostnode["name"]
        end
        hostnode.css("ReportItem").each do |itemnode|
            if (itemnode["port"] != "0" && itemnode["severity"] > "0")

                # create a temporary finding object
                finding = Findings.new()
                finding.title = itemnode['pluginName'].to_s()
                finding.overview = clean(itemnode.css("description").to_s)
                finding.remediation = clean(itemnode.css("solution").to_s)

                # can this be inherited from an import properly?
                finding.type = "Imported"

                finding.risk = itemnode["severity"]

                # hardcode the DREAD score, the user should fix this
                finding.damage = 1
                finding.reproducability = 1
                finding.exploitability = 1
                finding.affected_users = 1
                finding.discoverability = 1
                finding.dread_total = 1

                finding.affected_hosts = hostnode["name"]

                if itemnode.css("plugin_output")
                    finding.notes = hostnode["name"]+" ("+itemnode["protocol"]+ " port " + itemnode["port"]+"):"+clean(itemnode.css("plugin_output").to_s)
                end

                finding.references = clean(itemnode.css("see_also").to_s)
                #to see if it can get the user name after import for each finding
                finding.owner_f=get_username
                findings << finding
                items << itemnode['pluginID'].to_s()
            end
        end
        vulns[host] = items
        items = []
    end

    vulns["findings"] = uniq_findings(findings)
    return vulns
end

def parse_burp_xml(xml)
    vulns = Hash.new
    findings = Array.new
    vulns["findings"] = []

    doc = Nokogiri::XML(xml)
    doc.css('//issues/issue').each do |issue|
        if issue.css('severity').text
            # create a temporary finding object
            finding = Findings.new()
            finding.title = clean(issue.css('name').text.to_s())
            finding.overview = clean(issue.css('issueBackground').text.to_s()+issue.css('issueDetail').text.to_s())
            finding.remediation = clean(issue.css('remediationBackground').text.to_s())

            if issue.css('severity').text == 'Low'
                finding.risk = 1
            elsif issue.css('severity').text == 'Medium'
                finding.risk = 2
            elsif issue.css('severity').text =='High'
                finding.risk = 3
            else
                finding.risk = 1
            end

            # hardcode the DREAD score, the user assign the risk
            finding.damage = 1
            finding.reproducability = 1
            finding.exploitability = 1
            finding.affected_users = 1
            finding.discoverability = 1
            finding.dread_total = 1
            finding.type = "Imported"

            findings << finding

            host = issue.css('host').text
            ip = issue.css('host').attr('ip')
            id = issue.css('type').text
            hostname = "#{ip} #{host}"

            finding.affected_hosts = "#{host} (#{ip})"
            #to see if it can get the user name after import for each finding
            finding.owner_f=get_username

            if vulns[hostname]
                vulns[hostname] << id
            else
                vulns[hostname] = []
                vulns[hostname] << id
            end
        end
    end

    vulns["findings"] = uniq_findings(findings)
    return vulns
end

# < hadhemi
def parse_acunetix_xml(xml)
    vulns = Hash.new
    findings = Array.new
    vulns["findings"] = []

    doc = Nokogiri::XML(xml)
    doc.css('ReportItem').each do |item|

            # create a temporary finding object
            finding = Findings.new()
            finding.title = clean(item.css('Name').text.to_s())
            finding.overview = clean(item.css('Description').text.to_s()+item.css('DetailedInformation').text.to_s())
            finding.remediation = clean(item.css('Recommendation').text.to_s())

            if item.css('Severity').text == 'low'
                finding.risk = 1
            elsif item.css('Severity').text == 'medium'
                finding.risk = 2
            elsif item.css('Severity').text =='high'
                finding.risk = 3
            else
                finding.risk = 1
            end

            # hardcode the DREAD score, the user assign the risk
            finding.damage = 1
            finding.reproducability = 1
            finding.exploitability = 1
            finding.affected_users = 1
            finding.discoverability = 1
            finding.dread_total = 1
            finding.type = "Imported"

            findings << finding

            host = item.css('Affects').text

            id = item.attr('id')
            hostname = "#{host}"
            #to see if it can get the user name after import for each finding
            finding.owner_f=get_username

            finding.affected_hosts = "#{host}"
            #finding.cvss_total=clean(item.css('Score').to_s)

            #cvss v3
            item.css("CVSS3").each do |itemcvss|

              #finding.cvss_base=clean(itemcvss.css('Score').to_s)
              #base score
              finding.cvss_total=clean(itemcvss.css('Score').to_s)
              finding.risk_cvss_v3=finding.risk

              finding.av=clean(itemcvss.css('AV').to_s)
              finding.ac=clean(itemcvss.css('AC').to_s)
              finding.pr=clean(itemcvss.css('PR').to_s)
              finding.ui=clean(itemcvss.css('UI').to_s)
              finding.s=clean(itemcvss.css('S').to_s)
              finding.c=clean(itemcvss.css('C').to_s)
              finding.i=clean(itemcvss.css('I').to_s)
              finding.a=clean(itemcvss.css('A').to_s)
              #temporal score
              finding.e=clean(itemcvss.css('E').to_s)
              finding.rl=clean(itemcvss.css('RL').to_s)
              finding.rc=clean(itemcvss.css('RC').to_s)
              #enviromental score
              finding.mav=clean(itemcvss.css('MAV').to_s)
              finding.mac=clean(itemcvss.css('MAC').to_s)
              finding.mpr=clean(itemcvss.css('MPR').to_s)
              finding.mui=clean(itemcvss.css('MUI').to_s)
              finding.ms=clean(itemcvss.css('MS').to_s)
              finding.mc=clean(itemcvss.css('MC').to_s)
              finding.mi=clean(itemcvss.css('MI').to_s)
              finding.ma=clean(itemcvss.css('MA').to_s)
              
              finding.cr=clean(itemcvss.css('CR').to_s)
              finding.ir=clean(itemcvss.css('IR').to_s)
              finding.ar=clean(itemcvss.css('AR').to_s)

            end

            item.css("CVSS").each do |itemcvss|

              #finding.cvss_base=clean(itemcvss.css('Score').to_s)
              #base score
              finding.risk_cvss_v2=finding.risk
              finding.cvss_total2=clean(itemcvss.css('Score').to_s)

              finding.av2=clean(itemcvss.css('AV').to_s)
              finding.ac2=clean(itemcvss.css('AC').to_s)
              finding.au2=clean(itemcvss.css('Au').to_s)

              finding.c2=clean(itemcvss.css('C').to_s)
              finding.i2=clean(itemcvss.css('I').to_s)
              finding.a2=clean(itemcvss.css('A').to_s)
              #temporal score
              finding.e2=clean(itemcvss.css('E').to_s)
              finding.rl2=clean(itemcvss.css('RL').to_s)
              finding.rc2=clean(itemcvss.css('RC').to_s)
              #enviromental score
              finding.cdp=clean(itemcvss.css('CDP').to_s)
              finding.td=clean(itemcvss.css('TD').to_s)

              finding.cr2=clean(itemcvss.css('CR').to_s)
              finding.ir2=clean(itemcvss.css('IR').to_s)
              finding.ar2=clean(itemcvss.css('AR').to_s)

            end



            if vulns[hostname]
                vulns[hostname] << id
            else
                vulns[hostname] = []
                vulns[hostname] << id
            end
        end


    vulns["findings"] = uniq_findings(findings)
    return vulns
end
# > hadhemi
# < hadhemi
def parse_nikto_xml(xml)
 vulns = Hash.new
 findings = Array.new
 vulns["findings"] = []

 doc = Nokogiri::XML(xml)
 doc.css("//niktoscan").each do |hostnode|
  hostnode.css("scandetails").each do |itemnode|
    itemnode.css('item').each do |item|

            # create a temporary finding object
            finding = Findings.new()
            finding.title = clean(item.css('description').text.to_s())

            # hardcode the DREAD score, the user assign the risk
            finding.damage = 1
            finding.reproducability = 1
            finding.exploitability = 1
            finding.affected_users = 1
            finding.discoverability = 1
            finding.dread_total = 1
            finding.type = "Imported"
            finding.risk =1

            findings << finding

            host = clean(item.css('namelink').text)
            ip = clean(item.css('iplink').text)

            id = item.attr('id')
            hostname = "#{ip} #{host}"

            #to see if it can get the user name after import for each finding
            finding.owner_f=get_username

            finding.affected_hosts = "#{host} (#{ip})"

            if vulns[hostname]
                vulns[hostname] << id
            else
                vulns[hostname] = []
                vulns[hostname] << id
            end

    end
  end
 end

    vulns["findings"] = uniq_findings(findings)
    return vulns
end
# > hadhemi
