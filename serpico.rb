# encoding: ASCII-8BIT
require 'rubygems'
require 'bundler/setup'
require 'sinatra'
require 'haml'
require 'zipruby'
require 'net/ldap'
require 'json'

#serpico handlers
require './model/master'
require './helpers/helper'
require './helpers/sinatra_ssl'
require './helpers/xslt_generation'
require './helpers/vuln_importer'
require './helpers/asciidoc_exporter'

# import config options
config_options = JSON.parse(File.read('./config.json'))


## SSL Settings
set :ssl_certificate, config_options["ssl_certificate"]
set :ssl_key, config_options["ssl_key"]
set :port, config_options["port"]
set :bind, "0.0.0.0"

## Global variables
set :finding_types, config_options["finding_types"]
set :effort, ["Quick","Planned","Involved"]
set :assessment_types, ["External", "Internal", "Internal/External", "Wireless", "Web Application", "DoS"]
set :status, ["EXPLOITED"]
set :show_exceptions, true

# CVSS
set :av2, ["Local","Adjacent Network","Network"] #cvss v2
set :ac2, ["High","Medium","Low"] #cvss v2
set :au2, ["Multiple","Single","None"] #cvss v2
set :c2, ["None","Partial","Complete"] #cvss v2
set :i2, ["None","Partial","Complete"] #cvss v2
set :a2, ["None","Partial","Complete"] #cvss v2
set :e2, ["Not Defined","Unproven Exploit Exists","Proof-of-Concept Code","Functional Exploit Exists","High"]
set :rl2, ["Not Defined","Official Fix","Temporary Fix","Workaround","Unavailable"]
set :rc2, ["Not Defined","Unconfirmed","Uncorroborated","Confirmed"]#cvss v2
set :cdp, ["Not Defined","None","Low","Low-Medium","Medium-High","High"] #cvss v2
set :td, ["Not Defined","None","Low","Medium","High"] #cvss v2
set :cr2, ["Not Defined","Low","Medium","High"]
set :ir2, ["Not Defined","Low","Medium","High"]
set :ar2, ["Not Defined","Low","Medium","High"]

set :av, ["Local","Adjacent Network","Network" , "Physical"] #cvss v3
set :ac, ["High","Low"]
set :ui, ["Required","None"] #cvss v3
set :pr, ["None","Low","High"] #cvss v3
set :s, ["Unchanged","Changed"] #cvss v3
set :c, ["None","Low","High"]
set :i, ["None","Low","High"]
set :a, ["None","Low","High"]
set :e, ["Not Defined","Unproven Exploit Exists","Proof-of-Concept Code","Functional Exploit Exists","High"]
set :rl, ["Not Defined","Official Fix","Temporary Fix","Workaround","Unavailable"]
set :rc, ["Not Defined","Unknown","Reasonable","Confirmed"]#cvss v3
set :mav, ["Not Defined","Local","Adjacent Network","Network" , "Physical"] #cvss v3
set :mac, ["Not Defined","High","Low"]
set :mui, ["Not Defined","Required","None"] #cvss v3
set :mpr, ["Not Defined","None","Low","High"] #cvss v3
set :ms, ["Not Defined","Unchanged","Changed"] #cvss v3
set :mc, ["Not Defined","None","Low","High"]
set :mi, ["Not Defined","None","Low","High"]
set :ma, ["Not Defined","None","Low","High"]
set :ir, ["Not Defined","Low","Medium","High"]
set :ar, ["Not Defined","Low","Medium","High"]


## LDAP Settings
if config_options["ldap"].downcase == "true"
    set :ldap, true
else
    set :ldap, false
end
set :domain, config_options["ldap_domain"]
set :dc, config_options["ldap_dc"]

enable :sessions
set :session_secret, rand(36**12).to_s(36)
set :cr, ["Not Defined","Low","Medium","High"]

### Basic Routes

# Used for 404 responses
not_found do
    "Sorry, I don't know this page."
end

# Error catches
error do
    if settings.show_exceptions
        "Error!"+ env['sinatra.error'].name
    else
        "Error!! Check the process dump for the error or turn show_exceptions on to show in the web interface."
    end
end

# Run a session check on every route
["/info","/reports/*","/report/*","/","/logout","/admin/*","/master/*","/mapping/*"].each do |path|
    before path do
        next if request.path_info == "/reports/list"
        redirect '/reports/list' unless valid_session?
    end

end

before "/master/*" do
    redirect to("/no_access") if not is_administrator?
end

before "/mapping/*" do
    redirect to("/no_access") if not is_administrator?
end
#######


get '/' do
    redirect to("/reports/list")
end

get '/login' do
    redirect to("/reports/list")
end

# Handles the consultant information settings
get '/info' do
    @user = User.first(:username => get_username)
    if @user.type =="Administrator"
      @admin=true
    end
    if !@user
        @user = User.new
        @user.auth_type = "AD"
        @user.username = get_username
        @user.type = "User"
        @user.save
    end

    #haml :info, :encode_html => true
    erb :info
end

# Save the consultant information into the database
post '/info' do
    @user = User.first(:username => get_username)
    if @user.type =="Administrator"
      @admin=true
    end
    if !@user
        @user = User.new
        @user.auth_type = "AD"
        @user.username = get_username
        @user.type = "User"
    end

    @user.consultant_email = params[:email]
    @user.consultant_phone = params[:phone]
    @user.consultant_title = params[:title]
    @user.consultant_name = params[:name]
    @user.save

    redirect to("/info")
end

post '/login' do
    user = User.first(:username => params[:username])

    if user and user.auth_type == "Local"

        usern = User.authenticate(params["username"], params["password"])

        if usern and session[:session_id]
            # replace the session in the session table
            # TODO : This needs an expiration, session fixation
            @del_session = Sessions.first(:username => "#{usern}")
            @del_session.destroy if @del_session
            @curr_session = Sessions.create(:username => "#{usern}",:session_key => "#{session[:session_id]}")
            @curr_session.save

        end
    else
		if options.ldap
			#try AD authentication
			usern = params[:username]
			data = url_escape_hash(request.POST)
            if usern == "" or params[:password] == ""
                redirect to("/")
            end

			user = "#{options.domain}\\#{data["username"]}"
			ldap = Net::LDAP.new :host => "#{options.dc}", :port => 636, :encryption => :simple_tls, :auth => {:method => :simple, :username => user, :password => params[:password]}

			if ldap.bind
			   # replace the session in the session table
			   @del_session = Sessions.first(:username => "#{usern}")
			   @del_session.destroy if @del_session
			   @curr_session = Sessions.create(:username => "#{usern}",:session_key => "#{session[:session_id]}")
			   @curr_session.save
			end
		end
    end
#<hadhemi
@username=params[:username]
#>hadhemi
    redirect to("/")
end

## We use a persistent session table, one session per user; no end date
get '/logout' do
    if session[:session_id]
        sess = Sessions.first(:session_key => session[:session_id])
        if sess
            sess.destroy
        end
    end

    redirect to("/")
end

# rejected access (admin functionality)
get "/no_access" do
    return "Sorry. You Do Not have access to this resource."
end

######
# Admin Interfaces
######

get '/admin/' do
    redirect to("/no_access") if not is_administrator?
    @admin = true

    #haml :admin, :encode_html => true
    erb :admin
end

get '/admin/add_user' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    #haml :add_user, :encode_html => true
    erb :add_user
end

# serve a copy of the code
get '/admin/pull' do
    redirect to("/no_access") if not is_administrator?

	if File.exists?("./export.zip")
		send_file "./export.zip", :filename => "export.zip", :type => 'Application/octet-stream'
	else
		"No copy of the code available. Run scripts/make_export.sh."
	end
end

# Create a new user
post '/admin/add_user' do
    redirect to("/no_access") if not is_administrator?

    user = User.first(:username => params[:username])

    if user
        if params[:password]
            # we have to hardcode the input params to prevent param pollution
            user.update(:type => params[:type], :auth_type => params[:auth_type], :password => params[:password])
        else
            # we have to hardcode the params to prevent param pollution
            user.update(:type => params[:type], :auth_type => params[:auth_type])
        end
    else
        user = User.new
        user.username = params[:username]
        user.password = params[:password]
        user.type = params[:type]
        user.auth_type = params[:auth_type]
        user.save
    end

    redirect to('/admin/list_user')
end

get '/admin/list_user' do
    redirect to("/no_access") if not is_administrator?
    @admin = true
    @users = User.all

    #haml :list_user, :encode_html => true
    erb :list_user
end

get '/admin/edit_user/:id' do
    redirect to("/no_access") if not is_administrator?

    @user = User.first(:id => params[:id])
    @admin=true
    #haml :add_user, :encode_html => true
    #erb :add_user
    erb :edit_user
end

get '/admin/delete/:id' do
    redirect to("/no_access") if not is_administrator?

    @user = User.first(:id => params[:id])
    @user.destroy if @user

    redirect to('/admin/list_user')
end

get '/admin/add_user/:id' do
    if not is_administrator?
        id = params[:id]
        unless get_report(id)
            redirect to("/no_access")
        end
    end

    @users = User.all(:order => [:username.asc])
    @report = Reports.first(:id => params[:id])

    if is_administrator?
      @admin = true
    end

    #haml :add_user_report, :encode_html => true
    erb :add_user_report
end

post '/admin/add_user/:id' do
    if not is_administrator?
        id = params[:id]
        unless get_report(id)
            redirect to("/no_access")
        end
    end

    report = Reports.first(:id => params[:id])

    if report == nil
        return "No Such Report"
    end

    authors = report.authors

    if authors
        authors = authors.push(params[:author])
        puts authors
        puts "ici"
    else
        authors = ["#{params[:author]}"]
        puts authors
        puts "la ba"
    end

    report.authors = authors
    report.save

    redirect to("/reports/list")
end

get '/admin/del_user_report/:id/:author' do
    if not is_administrator?
        id = params[:id]
        unless get_report(id)
            redirect to("/no_access")
        end
    end

    report = Reports.first(:id => params[:id])

    if report == nil
        return "No Such Report"
    end

    authors = report.authors

    if authors
        authors = authors - ["#{params[:author]}"]
        puts "del"
        puts authors
    end

    report.authors = authors
    report.save

    redirect to("/reports/list")
end

######
# Template Document Routes
######

# These are the master routes, they control the findings database

# List Available Templated Findings
get '/master/findings' do
    @findings = TemplateFindings.all(:order => [:title.asc])
    @master = true
    @dread = config_options["dread"]
    @cvss = config_options["cvss"]

    #haml :findings_list, :encode_html => true
    erb :findings_list
end

# Create a new templated finding
get '/master/findings/new' do
    @master = true
    @dread = config_options["dread"]
    @cvss = config_options["cvss"]
    @nessusmap = config_options["nessusmap"]

    #haml :create_finding, :encode_html => true
    erb :create_finding
end

# Create the finding in the DB
post '/master/findings/new' do
    data = url_escape_hash(request.POST)

    if(config_options["dread"])
        data["dread_total"] = data["damage"].to_i + data["reproducability"].to_i + data["exploitability"].to_i + data["affected_users"].to_i + data["discoverability"].to_i
    end

    # split out any nessus mapping data
    nessusdata = Hash.new()
    nessusdata["pluginid"] = data["pluginid"]
    data.delete("pluginid")

    @finding = TemplateFindings.new(data)
    @finding.save

    # find the id of the newly created finding so we can link mappings to it
    @newfinding = TemplateFindings.first(:title => data["title"], :order => [:id.desc], :limit => 1)

    # save nessus mapping
    if(config_options["nessusmap"])
        #nessusdata["templatefindings_id"] = @newfinding.id

        #@nessus = NessusMapping.new(nessusdata)
        #@nessus.save
    elsif(config_options["cvss"])

        data = cvss(data)
        data = cvss3(data)
    end

    redirect to('/master/findings')
end

# Edit the templated finding
get '/master/findings/:id/edit' do
    @master = true
    @dread = config_options["dread"]
    @cvss = config_options["cvss"]
    @nessusmap = config_options["nessusmap"]
    @burpmap = config_options["burpmap"]

    # Check for kosher name in report name
    id = params[:id]

    # Query for all Findings
    @finding = TemplateFindings.first(:id => id)
	@templates = Xslt.all()

    if (@nessusmap)
        #@nessus = NessusMapping.all(:templatefindings_id => id)
    end

    if (@burpmap)
        #@burp = BurpMapping.all(:templatefindings_id => id)
    end

    if @finding == nil
        return "No Such Finding"
    end

    #haml :findings_edit, :encode_html => true
    erb :findings_edit
end

# Edit a finding
post '/master/findings/:id/edit' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for all Findings
    @finding = TemplateFindings.first(:id => id)

    if @finding == nil
        return "No Such Finding"
    end

    data = url_escape_hash(request.POST)

    if data["approved"] == "on"
        data["approved"] = true
    else
        data["approved"] = false
    end

    if(config_options["dread"])
        data["dread_total"] = data["damage"].to_i + data["reproducability"].to_i + data["exploitability"].to_i + data["affected_users"].to_i + data["discoverability"].to_i
    elsif(config_options["cvss"])
        data = cvss(data)
        #< hadhemi
        data = cvss3(data)
        #>hadhemi

    end

    # split out any nessus mapping data
    nessusdata = Hash.new()
    nessusdata["pluginid"] = data["nessus_pluginid"]
    data.delete("nessus_pluginid")
    nessusdata["templatefindings_id"] = id

    # split out any burp mapping data
    burpdata = Hash.new()
    burpdata["pluginid"] = data["burp_pluginid"]
    data.delete("burp_pluginid")
    burpdata["templatefindings_id"] = id

    # Update the finding with templated finding stuff
    @finding.update(data)

    # save nessus mapping data to db
    if(config_options["nessusmap"])
        #@nessus = NessusMapping.new(nessusdata)
        #@nessus.save
    end

    # save burp mapping data to db
    if(config_options["burpmap"])
        #@burp = BurpMapping.new(burpdata)
        #@burp.save
    end

    redirect to("/master/findings")
end

# Delete a mapping from finding
get '/mapping/:id/nessus/:mappingid/delete' do
    # Check for kosher name in report name
    #id = params[:id]

    #mappingid = params[:mappingid]

    #@map = NessusMapping.first(:templatefindings_id => id, :pluginid => mappingid)

    #@map.destroy
    redirect to("/master/findings/#{id}/edit")
end

# Delete a mapping from finding
get '/mapping/:id/burp/:mappingid/delete' do
    # Check for kosher name in report name
    #id = params[:id]

    #mappingid = params[:mappingid]

    #@map = BurpMapping.first(:templatefindings_id => id, :pluginid => mappingid)

    #@map.destroy
    redirect to("/master/findings/#{id}/edit")
end

# Delete a template finding
get '/master/findings/:id/delete' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for all Findings
    @finding = TemplateFindings.first(:id => id)

    if @finding == nil
        return "No Such Finding"
    end

    # Update the finding with templated finding stuff
    @finding.destroy

    redirect to("/master/findings")
end

# preview a finding
get '/master/findings/:id/preview' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for all Findings
    @finding = TemplateFindings.first(:id => id)

    if @finding == nil
        return "No Such Finding"
    end

    ## We have to do some hackery here for wordml
    findings_xml = ""
    findings_xml << "<findings_list>"
    findings_xml << @finding.to_xml
    findings_xml << "</findings_list>"

    findings_xml = meta_markup_unencode(findings_xml, nil)

    # this is the master db so we have to do a bait and switch
    # The other option is creating a master finding specific docx
    findings_xml = findings_xml.gsub("<template_findings>","<findings>")
    findings_xml = findings_xml.gsub("</template_findings>;","</template_findings>")

    report_xml = "#{findings_xml}"

	xslt_elem = Xslt.first(:finding_template => true)

	if xslt_elem

		# Push the finding from XML to XSLT
		xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

		docx_xml = xslt.transform(Nokogiri::XML(report_xml))

		# We use a temporary file with a random name
		rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

		# Create a temporary copy of the finding_template
		FileUtils::copy_file(xslt_elem.docx_location,rand_file)

		# A better way would be to create the zip file in memory and return to the user, this is not ideal
		Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
			zipfile.add_or_replace_buffer('word/document.xml',
										  docx_xml.to_s)
		end

		send_file rand_file, :type => 'docx', :filename => "#{@finding.title}.docx"

	else
		"You don't have a Finding Template (did you delete the temp?) -_- ... If you're an admin go to <a href='/admin/templates/add'>here</a> to add one.'"
	end
end

# Export a findings database
get '/master/export' do
	json = ""

	findings = TemplateFindings.all

	local_filename = "./tmp/#{rand(36**12).to_s(36)}.json"
    File.open(local_filename, 'w') {|f| f.write(JSON.pretty_generate(findings)) }

	send_file local_filename, :type => 'json', :filename => "template_findings.json"
end

# Import a findings database
get '/master/import' do
	#haml :import_templates
  @master=true
  erb :import_templates
end

# Import a findings database
post '/master/import' do
	# reject if the file is above a certain limit
  if params[:file]
	if params[:file][:tempfile].size > 1000000
		return "File too large. 1MB limit"
	end

	json_file = params[:file][:tempfile].read
	line = JSON.parse(json_file)

	line.each do |j|
		j["id"] = nil

		finding = TemplateFindings.first(:title => j["title"])

		if finding
			#the finding title already exists in the database
			if finding["overview"] == j["overview"] and finding["remediation"] == j["remediation"]
				# the finding already exists, ignore it
			else
				# it's a modified finding
				j["title"] = "#{j['title']} - [Uploaded Modified Templated Finding]"
				params[:approved] !=nil ? j["approved"] = true : j["approved"] = false
                f = TemplateFindings.create(j)
				f.save
			end
		else
			params[:approved] != nil ? j["approved"] = true : j["approved"] = false
			f = TemplateFindings.first_or_create(j)
			f.save
		end
	end
  @master=true
end
	redirect to("/master/findings")
end

# Manage Templated Reports
get '/admin/templates' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    # Query for all Findings
    @templates = Xslt.all(:order => [:report_type.asc])

    #haml :template_list, :encode_html => true
    erb :template_list
end

# Manage Templated Reports
get '/admin/templates/add' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    #haml :add_template, :encode_html => true
    erb :add_template
end

# Manage Templated Reports
get '/admin/templates/:id/download' do
    redirect to("/no_access") if not is_administrator?

    @admin = true

    xslt = Xslt.first(:id => params[:id])

    send_file xslt.docx_location, :type => 'docx', :filename => "#{xslt.report_type}.docx"
end

get '/admin/delete/templates/:id' do
    redirect to("/no_access") if not is_administrator?

    @xslt = Xslt.first(:id => params[:id])

	if @xslt
		@xslt.destroy
		File.delete(@xslt.xslt_location)
		File.delete(@xslt.docx_location)
	end
    redirect to('/admin/templates')
end


# Manage Templated Reports
post '/admin/templates/add' do
    redirect to("/no_access") if not is_administrator?
    redirect to("/admin/templates") if !params[:file]
    @admin = true

	xslt_file = "./templates/#{rand(36**36).to_s(36)}.xslt"

	# reject if the file is above a certain limit
	if params[:file][:tempfile].size > 100000000
		return "File too large. 10MB limit"
	end

	docx = "./templates/#{rand(36**36).to_s(36)}.docx"
	File.open(docx, 'wb') {|f| f.write(params[:file][:tempfile].read) }

    error = false
    detail = ""
    begin
	    xslt = generate_xslt(docx)
    rescue ReportingError => detail
        error = true
    end


    if error
        "The report template you uploaded threw an error when parsing:<p><p> #{detail.errorString}"
    else

    	# open up a file handle and write the attachment
	    File.open(xslt_file, 'wb') {|f| f.write(xslt) }

	    # delete the file data from the attachment
	    datax = Hash.new
	    # to prevent traversal we hardcode this
	    datax["docx_location"] = "#{docx}"
	    datax["xslt_location"] = "#{xslt_file}"
	    datax["description"] = 	params[:description]
	    datax["report_type"] = params[:report_type]
	    data = url_escape_hash(datax)
	    data["finding_template"] = params[:finding_template] ? true : false
	    data["status_template"] = params[:status_template] ? true : false

	    @current = Xslt.first(:report_type => data["report_type"])

	    if @current
		    @current.update(:xslt_location => data["xslt_location"], :docx_location => data["docx_location"], :description => data["description"])
	    else
		    @template = Xslt.new(data)
		    @template.save
	    end

	    redirect to("/admin/templates")

        #haml :add_template, :encode_html => true
        erb :add_template
    end
end

# Manage Templated Reports
get '/admin/templates/:id/edit' do
    redirect to("/no_access") if not is_administrator?

    @admin = true
    @template = Xslt.first(:id => params[:id])

    #haml :edit_template, :encode_html => true
    erb :edit_template
end

# Manage Templated Reports
post '/admin/templates/edit' do
    redirect to("/no_access") if not is_administrator?

    @admin = true
    template = Xslt.first(:id => params[:id])

    xslt_file = template.xslt_location

    # reject if the file is above a certain limit
    if params[:file][:tempfile].size > 100000000
        return "File too large. 10MB limit"
    end

    docx = "./templates/#{rand(36**36).to_s(36)}.docx"
    File.open(docx, 'wb') {|f| f.write(params[:file][:tempfile].read) }

    error = false
    detail = ""
    begin
	    xslt = generate_xslt(docx)
    rescue ReportingError => detail
        error = true
    end

    if error
        "The report template you uploaded threw an error when parsing:<p><p> #{detail.errorString}"
    else

    	# open up a file handle and write the attachment
	    File.open(xslt_file, 'wb') {|f| f.write(xslt) }

	    # delete the file data from the attachment
	    datax = Hash.new
	    # to prevent traversal we hardcode this
	    datax["docx_location"] = "#{docx}"
	    datax["xslt_location"] = "#{xslt_file}"
	    datax["description"] = 	params[:description]
	    datax["report_type"] = params[:report_type]
	    data = url_escape_hash(datax)
	    data["finding_template"] = params[:finding_template] ? true : false
	    data["status_template"] = params[:status_template] ? true : false

	    @current = Xslt.first(:report_type => data["report_type"])

	    if @current
		    @current.update(:xslt_location => data["xslt_location"], :docx_location => data["docx_location"], :description => data["description"])
	    else
		    @template = Xslt.new(data)
		    @template.save
	    end

	    redirect to("/admin/templates")
    end
end

#####
# Reporting Routes
#####

# List current reports
get '/reports/list' do
    @reports = get_reports
    #<hadhemi
    #@user = User.first(:username => get_username)
    @userV=get_username

    @keys=[]
    @values=[]

    @reports_per_month=get_reports_per_month

    @reports_by_type=get_reports_by_type

    @reports_by_client=get_reports_by_client
    @reports_by_client.each {|key, value|  @keys.push("#{key}") and @values.push("#{value}")  }

    #>hadhemi
    @admin = true if is_administrator?

	# allow the user to set their logo in the configuration options
	@logo = config_options["logo"]

    #haml :reports_list, :encode_html => true
    erb :reports_list
end

# Create a report
get '/report/new' do

    @templates = Xslt.all
    #haml :new_report, :encode_html => true
    erb :new_report
end

# Create a report
post '/report/new' do

    data = url_escape_hash(request.POST)
    #hadhemi to prevent creating a report with an empty name or empty score or existing name
    verif=true
    @reports=Reports.all
    @reports.each do |rep|
      if rep.report_name==data["report_name"]
        verif=false
      end
    end

    if (data["report_name"]!="" and data["report_scoring"]!="" and verif)
    data["owner"] = get_username
    data["date"] = DateTime.now.strftime "%m/%d/%Y"

    @report = Reports.new(data)
    @report.save
    redirect to("/report/#{@report.id}/edit")
  else
    redirect to("/report/new")
  end
end

# List attachments
get '/report/:id/attachments' do
    id = params[:id]

    # Query for the first report matching the id
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    @attachments = Attachments.all(:report_id => id)
    haml :list_attachments, :encode_html => true
end

# upload nessus xml files to be processed
get '/report/:id/import_nessus' do
    id = params[:id]

    @nessusmap = config_options["nessusmap"]

    # Query for the first report matching the id
    @report = get_report(id)

    #haml :import_nessus, :encode_html => true
    erb :import_nessus
end

# upload nessus xml files to be processed
get '/report/:id/import_nikto' do
    id = params[:id]

    @niktomap = config_options["niktomap"]

    # Query for the first report matching the id
    @report = get_report(id)

    erb :import_nikto
end

# auto add serpico findings if mapped to nessus ids
post '/report/:id/import_autoadd' do
    type = params[:type]
if params[:file]
    xml = params[:file][:tempfile].read
    if (xml =~ /^<NessusClientData_v2>/ && type == "nessus")
        import_nessus = true
        vulns = parse_nessus_xml(xml)
    elsif (xml =~ /^<issues burpVersion/ && type == "burp")
        import_burp = true
        vulns = parse_burp_xml(xml)
        # hadhemi <
    elsif (xml =~ /^<ScanGroup ExportedOn/ && type == "acunetix")
        import_acunetix = true
        vulns = parse_acunetix_xml(xml)
        #puts vulns;
    elsif (xml =~ /^<!DOCTYPE niktoscan/ && type == "nikto")
        import_nikto = true
        vulns = parse_nikto_xml(xml)
        # > hadhemi
    else
        return "File does not contain valid XML import data"
    end
else
  "error"
end


    # reject if the file is above a certain limit
    #if params[:file][:tempfile].size > 1000000
    #        return "File too large. 1MB limit"
    #end
    # Check for kosher name in report name
    id = params[:id]

    add_findings = Array.new
    dup_findings = Array.new
    autoadd_hosts = Hash.new

    # Query for the first report matching the report_name
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    # load all findings
    @findings = TemplateFindings.all(:order => [:title.asc])

    # parse nessus xml into hash
    #nessus_vulns = parse_nessus_xml(nessus_xml)

    # determine findings to add from vuln data
    # host/ip is key, value is array of vuln ids
    if vulns
    vulns.keys.each do |i|
        vulns[i].each do |v|

			# if serpico finding id maps to nessus/burp plugin id, add to report
            #if import_nessus
            #    @mappings = NessusMapping.all(:pluginid => v)
            #elsif import_burp
            #    @mappings = BurpMapping.all(:pluginid => v)
            # hadhemi <
            #elsif import_acunetix
              #  @mappings = AcunetixMapping.all(:pluginid => v)
            # hadhemi >
            #end
            # add affected hosts for each finding
            if (@mappings)
                @mappings.each do |m|
                    if autoadd_hosts[m.templatefindings_id]
                        # only one host/url per finding (regardless of ports and urls). this should change in the future
                        if not autoadd_hosts[m.templatefindings_id].include?(i)
                            autoadd_hosts[m.templatefindings_id] << i
                        end
                    else
                        autoadd_hosts[m.templatefindings_id] = []
                        autoadd_hosts[m.templatefindings_id] << i
                    end
                    add_findings << m.templatefindings_id
                end
            end
        end
    end


    add_findings = add_findings.uniq

    # create new findings from an import
    # TODO: This will duplicate if the user already has a nessus id mapped
    if config_options["auto_import"]
        vulns["findings"].each do |vuln|
            vuln.report_id = id
            vuln.save
        end
    end
end
    if add_findings.size == 0
        redirect to("/report/#{id}/findings")
    else
        @autoadd = true

        add_findings.each do |finding|
            # if the finding already exists in the report dont add
            currentfindings = Findings.all(:report_id => id)
            currentfindings.each do |cf|
                if cf.master_id == finding.to_i
                    if not dup_findings.include?(finding.to_i)
                        dup_findings << finding.to_i
                    end
                    add_findings.delete(finding.to_i)
                end
            end
        end
        @autoadd_hosts = autoadd_hosts
        @dup_findings = dup_findings.uniq
        @autoadd_findings = add_findings
    end
    #haml :findings_add, :encode_html => true
    erb :findings_add
end

# upload burp xml files to be processed
get '/report/:id/import_burp' do
    id = params[:id]

    @burpmap = config_options["burpmap"]

    # Query for the first report matching the id
    @report = get_report(id)

    #haml :import_burp, :encode_html => true
    erb :import_burp
end

# < hedhemi
# upload acunetix xml files to be processed
get '/report/:id/import_acunetix' do
    id = params[:id]

    @acunetixmap = config_options["acunetixmap"]

    # Query for the first report matching the id
    @report = get_report(id)

    #haml :import_acunetix, :encode_html => true
    erb :import_acunetix
end
# > hedhemi

# Upload attachment menu
get '/report/:id/upload_attachments' do
    id = params[:id]
    @no_file = params[:no_file]

    # Query for the first report matching the id
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    @attachments = Attachments.all(:report_id => id)

    haml :upload_attachments, :encode_html => true
end

post '/report/:id/upload_attachments' do
    id = params[:id]

    # Query for the first report matching the id
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    if params[:file] == nil
    	redirect to("/report/#{id}/upload_attachments?no_file=1")
    end

    # We use a random filename
    rand_file = "./attachments/#{rand(36**36).to_s(36)}"

	# reject if the file is above a certain limit
	if params[:file][:tempfile].size > 100000000
		return "File too large. 100MB limit"
	end

	# open up a file handle and write the attachment
	File.open(rand_file, 'wb') {|f| f.write(params[:file][:tempfile].read) }

	# delete the file data from the attachment
	datax = Hash.new
	# to prevent traversal we hardcode this
	datax["filename_location"] = "#{rand_file}"
	datax["filename"] = params[:file][:filename]
	datax["description"] = CGI::escapeHTML(params[:description]).gsub(" ","_").gsub("/","_")
	datax["report_id"] = id
	data = url_escape_hash(datax)

	@attachment = Attachments.new(data)
	@attachment.save
	redirect to("/report/#{id}/attachments")
end

# display attachment
get '/report/:id/attachments/:att_id' do
    id = params[:id]

    # Query for the first report matching the id
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    @attachment = Attachments.first(:report_id => id, :id => params[:att_id])
    send_file @attachment.filename_location, :filename => "#{@attachment.filename}"
end

#Delete an attachment
get '/report/:id/attachments/delete/:att_id' do
    id = params[:id]

    # Query for the first report matching the id
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    @attachment = Attachments.first(:report_id => id, :id => params[:att_id])

	if @attachment == nil
		return "No Such Attachment"
	end

    File.delete(@attachment.filename_location)

    # delete the entries
    @attachment.destroy

	redirect to("/report/#{id}/attachments")
end


#Delete a report
get '/report/:id/remove' do
    id = params[:id]

    # Query for the first report matching the id
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    # get all findings associated with the report
    @findings = Findings.all(:report_id => id)

    # delete the entries
    @findings.destroy
    @report.destroy

    redirect to("/reports/list")
end

# Edit the Report's main information; Name, Consultant, etc.
get '/report/:id/edit' do
    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)
	  @templates = Xslt.all(:order => [:report_type.asc])

    # get all findings associated with the report
    @findings = Findings.all(:report_id => id)
    @nb=findings_number(@findings)

    if @report == nil
        return "No Such Report"
    end

    #haml :report_edit, :encode_html => true
    erb :report_edit
end

# Edit the Report's main information; Name, Consultant, etc.
get '/report/:id/additional_features' do
    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    #haml :additional_features, :encode_html => true
    erb :additional_features
end


# Edit a report
post '/report/:id/edit' do
    id = params[:id]

    data = url_escape_hash(request.POST)

    # get all findings associated with the report
    @findings = Findings.all(:report_id => id)
    @nb=findings_number(@findings)
    @report = get_report(id)
    @report = @report.update(data)

    redirect to("/report/#{id}/edit")
end

#Edit user defined variables
get '/report/:id/user_defined_variables' do
    id = params[:id]
    @report = get_report(id)

    if  @report.user_defined_variables
        @user_variables = JSON.parse(@report.user_defined_variables)
        @user_variables.each do |k,v|
			if v
				@user_variables[k] = meta_markup(v)
			end
        end
    else
        @user_variables = ""
    end

    haml :user_defined_variable, :encode_html => true
end

#Post user defined variables
post '/report/:id/user_defined_variables' do
    data = url_escape_hash(request.POST)

	variable_hash = Hash.new()
	data.each do |k,v|
		if k =~ /variable_name/
			key = k.split("variable_name_").last.split("_").first

			# remove certain elements from name %&"<>
			v = v.gsub("%","_").gsub("&quot;","'").gsub("&amp;","").gsub("&gt;","").gsub("&lt;","")
			variable_hash["#{key}%#{v}"] = "DEFAULT"

		end
		if k =~ /variable_data/
			key = k.split("variable_data_").last.split("_").first

			variable_hash.each do |k1,v1|
				if k1 =~ /%/
					kk = k1.split("%")
					if kk.first == key
						variable_hash[k1] = v
					end
				end
			end
		end
	end

	# remove the % and any blank values
	q = variable_hash.clone
	variable_hash.each do |k,v|
		if k =~ /%/
			p k.split("%")
			if k.split("%").size == 1
				q.delete(k)
			else
				q[k.split("%").last] = v
				q.delete(k)
			end
		end
	end
	variable_hash = q

    id = params[:id]
    @report = get_report(id)

    @report.user_defined_variables = variable_hash.to_json
    @report.save
    redirect to("/report/#{id}/user_defined_variables")

end

# Findings List Menu
get '/report/:id/findings' do
    @chart = config_options["chart"]

    @report = true
    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    # Query for the findings that match the report_id
    if(config_options["dread"])
        @findings = Findings.all(:report_id => id, :order => [:dread_total.desc])
    # < hadhemi
    # j'ai commenté ça pour que le classement se fait toujours par risque
    #elsif(config_options["cvss"])
    #    @findings = Findings.all(:report_id => id, :order => [:cvss_total.desc])
    # > hadhemi
    else
        @findings = Findings.all(:report_id => id, :order => [:risk.desc])
    end

    @stat=findings_by_severity(@findings)


    @stats=findings_by_type(@findings)

    puts findings_by_auth(@findings)
    @auth=findings_by_auth(@findings)

    @dread = config_options["dread"]
    @cvss = config_options["cvss"]

    #haml :findings_list, :encode_html => true
    erb :findings_list
end

# Generate a status report from the current findings
get '/report/:id/status' do
    id = params[:id]

    # Query for the report
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    # Query for the findings that match the report_id
    if(config_options["dread"])
        @findings = Findings.all(:report_id => id, :order => [:dread_total.desc])
    elsif(config_options["cvss"])
        @findings = Findings.all(:report_id => id, :order => [:cvss_total.desc])
    else
        @findings = Findings.all(:report_id => id, :order => [:risk.desc])
    end

    ## We have to do some hackery here for wordml
    findings_xml = ""
    findings_xml << "<findings_list>"
    @findings.each do |finding|
        ### Let's find the diff between the original and the new overview and remediation
        master_finding = TemplateFindings.first(:id => finding.master_id)

        findings_xml << finding.to_xml
    end
    findings_xml << "</findings_list>"

    findings_xml = meta_markup_unencode(findings_xml, @report.short_company_name)

    report_xml = "#{findings_xml}"

	xslt_elem = Xslt.first(:status_template => true)

	if xslt_elem

		# Push the finding from XML to XSLT
		xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

		docx_xml = xslt.transform(Nokogiri::XML(report_xml))

		# We use a temporary file with a random name
		rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

		# Create a temporary copy of the finding_template
		FileUtils::copy_file(xslt_elem.docx_location,rand_file)

		### IMAGE INSERT CODE
		if docx_xml.to_s =~ /\[!!/
			# first we read in the current [Content_Types.xml]
			content_types = ""
			Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
				zipfile.fopen("[Content_Types].xml") do |f|
					content_types = f.read # read entry content
				end
			end

			# add the png and jpg handling to end of content types document
			if !(content_types =~ /image\/jpg/)
				content_types = content_types.sub("</Types>","<Default Extension=\"jpg\" ContentType=\"image/jpg\"/></Types>")
			end
			if !(content_types =~ /image\/png/)
				content_types = content_types.sub("</Types>","<Default Extension=\"png\" ContentType=\"image/png\"/></Types>")
			end
			if !(content_types =~ /image\/jpeg/)
				content_types = content_types.sub("</Types>","<Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/></Types>")
			end

			# replace the content types to support images
			Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
				 zipfile.add_or_replace_buffer("[Content_Types].xml",
				   content_types)
			end

			# replace all [!! image !!] in the document
			imgs = docx_xml.to_s.split("[!!")
			docx = imgs.first
			imgs.delete_at(0)

			imgs.each do |image_i|

				name = image_i.split("!!]").first.gsub(" ","")
				end_xml = image_i.split("!!]").last

				# search for the image in the attachments
				image = Attachments.first(:description => name, :report_id => id)

				# tries to prevent breakage in the case image dne
				if image
					docx = image_insert(docx, rand_file, image, end_xml)
				else
					docx << end_xml
				end

			end

		else
			# no images in finding
			docx = docx_xml.to_s
		end
		#### END IMAGE INSERT CODE

		# A better way would be to create the zip file in memory and return to the user, this is not ideal
		Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
			zipfile.add_or_replace_buffer('word/document.xml',
										  docx)
		end

		send_file rand_file, :type => 'docx', :filename => "status.docx"

	else
		"You don't have a Finding Template (did you delete the temp?) -_- ... If you're an admin go to <a href='/admin/templates/add'>here</a> to add one."
	end


end

# Add a finding to the report
get '/report/:id/findings_add' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    # Query for all Findings
    @findings = TemplateFindings.all(:approved => true, :order => [:title.asc])

    #haml :findings_add, :encode_html => true
    erb :findings_add
end

# Add a finding to the report
post '/report/:id/findings_add' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    hosts = ""

    redirect to("/report/#{id}/findings") unless params[:finding]

	params[:finding].each do |finding|
		templated_finding = TemplateFindings.first(:id => finding.to_i)

		templated_finding.id = nil
		attr = templated_finding.attributes
    #<hadhemi
    attr.delete(:id)
    #>hadhemi
		attr.delete(:approved)
		attr["master_id"] = finding.to_i
		@newfinding = Findings.new(attr)
		@newfinding.report_id = id

        # because of multiple scores we need to make sure all are set
        # => leave it up to the user to make the calculation if they switch mid report
        @newfinding.dread_total = 0 if @newfinding.dread_total == nil
        @newfinding.cvss_total = 0  if @newfinding.cvss_total == nil
        @newfinding.risk_cvss_v3 = 0 if @newfinding.risk_cvss_v3 == nil
        @newfinding.risk_cvss_v2 = 0 if @newfinding.risk_cvss_v2 == nil
        @newfinding.risk = 0 if @newfinding.risk == nil

		@newfinding.save
	end

    # if we have hosts add them to the findings too
    params[:finding].each do |number|
        # if there are hosts to add with a finding they'll have a param syntax of "findingXXX=ip1,ip2,ip3"
        @findingnum = "finding#{number}"
        #TODO: merge with existing hosts (if any) probably should handle this host stuff in the db
        finding = Findings.first(:report_id => id, :master_id => number.to_i)

        if (params["#{@findingnum}"] != nil)
            params["#{@findingnum}"].split(",").each do |ip|
                #TODO: this is dirty. also should support different delimeters instead of just newline
                hosts << "<paragraph>" + ip.to_s + "</paragraph>"
            end

            finding.affected_hosts = hosts
            hosts = ""
        end
        finding.save
    end

    if(config_options["dread"])
        @findings = Findings.all(:report_id => id, :order => [:dread_total.desc])
    elsif(config_options["cvss"])
      if @report.report_scoring=="CVSS v3"
        @findings = Findings.all(:report_id => id, :order => [:cvss_total.desc])
      else
        @findings = Findings.all(:report_id => id, :order => [:cvss_total2.desc])
      end
    else
        @findings = Findings.all(:report_id => id, :order => [:risk.desc])
    end

    @dread = config_options["dread"]
    @cvss = config_options["cvss"]

    #haml :findings_list, :encode_html => true
    erb :findings_list
end

# Create a new finding in the report
get '/report/:id/findings/new' do
    @dread = config_options["dread"]
    @cvss = config_options["cvss"]


    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)
    if @report == nil
        return "No Such Report"
    end

    puts "hey"
    puts @report.report_scoring
    #haml :create_finding, :encode_html => true
    erb :create_finding
end

# Create the finding in the DB
post '/report/:id/findings/new' do

  data = url_escape_hash(request.POST)

  id = params[:id]
  data["report_id"] = id

  # Query for the first report matching the report_name
  @report = get_report(id)
  if @report == nil
      return "No Such Report"
  end


    if(config_options["dread"])
        data["dread_total"] = data["damage"].to_i + data["reproducability"].to_i + data["exploitability"].to_i + data["affected_users"].to_i + data["discoverability"].to_i
    elsif(config_options["cvss"])
      if @report.report_scoring=="CVSS v2"
        data = cvss(data)

      elsif @report.report_scoring=="CVSS v3"
        #<hadhemi
        data = cvss3(data)
        #>hadhemi
      end
    end


    @finding = Findings.new(data)
    @finding.owner_f=get_username
    @finding.save

    # because of multiple scores we need to make sure all are set
    # => leave it up to the user to make the calculation if they switch mid report
    @finding.dread_total = 0 if @finding.dread_total == nil
    @finding.cvss_total = 0 if @finding.cvss_total == nil
    @finding.risk_cvss_v2 = 0 if @finding.risk_cvss_v2 == nil
    @finding.risk_cvss_v3 = 0 if @finding.risk_cvss_v3 == nil
    @finding.risk = 0 if @finding.risk == nil
    @finding.save

    # for a parameter_pollution on report_id
    redirect to("/report/#{id}/findings")
end

# Edit the finding in a report
get '/report/:id/findings/:finding_id/edit' do
    id = params[:id]

    # Query for the first report matching the report_name
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    finding_id = params[:finding_id]

    # Query for all Findings
    @finding = Findings.first(:report_id => id, :id => finding_id)

    if @finding == nil
        return "No Such Finding"
    end

    @dread = config_options["dread"]
    @cvss = config_options["cvss"]

    #haml :findings_edit, :encode_html => true
    erb :findings_edit
end

# Edit a finding in the report
post '/report/:id/findings/:finding_id/edit' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for the report
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    finding_id = params[:finding_id]

    # Query for all Findings
    @finding = Findings.first(:report_id => id, :id => finding_id)

    if @finding == nil
        return "No Such Finding"
    end

    data = url_escape_hash(request.POST)

    if(config_options["dread"])
        data["dread_total"] = data["damage"].to_i + data["reproducability"].to_i + data["exploitability"].to_i + data["affected_users"].to_i + data["discoverability"].to_i
    elsif(config_options["cvss"])
        #data = cvss(data)
        #<hadhemi
        #data = cvss3(data)
        #>hadhemi

    if @report.report_scoring=="CVSS v3"
      data = cvss3(data)
    elsif @report.report_scoring=="CVSS v2"
      data = cvss(data)
    else
      #dont do any cvss ,just regular score
    end
    end

    # Update the finding with templated finding stuff
    @finding.update(data)

    # because of multiple scores we need to make sure all are set
    # => leave it up to the user to make the calculation if they switch mid report
    @finding.dread_total = 0 if @finding.dread_total == nil
    @finding.cvss_total = 0 if @finding.cvss_total == nil
    @finding.risk = 0 if @finding.risk == nil
    @finding.risk_cvss_v3 = 0 if @finding.risk_cvss_v3 == nil
    @finding.risk_cvss_v2 = 0 if @finding.risk_cvss_v2 == nil
    @finding.save

    redirect to("/report/#{id}/findings")
end

# Upload a finding from a report into the database
get '/report/:id/findings/:finding_id/upload' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for the report
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    finding_id = params[:finding_id]

    # Query for the finding
    @finding = Findings.first(:report_id => id, :id => finding_id)

    if @finding == nil
        return "No Such Finding"
    end

    # We can't create a direct copy b/c TemplateFindings doesn't have everything findings does
    # Check model/master.rb to compare
    attr = {
                    :title => @finding.title,
                    :damage => @finding.damage,
                    :reproducability => @finding.reproducability,
                    :exploitability => @finding.exploitability,
#                    :affected_users => @finding.affected_users,
                    :discoverability => @finding.discoverability,
                    :dread_total => @finding.dread_total,
                    :cvss_base => @finding.cvss_base,
                    :cvss_impact => @finding.cvss_impact,
                    :cvss_exploitability => @finding.cvss_exploitability,
                    :cvss_temporal => @finding.cvss_temporal,
                    :cvss_environmental => @finding.cvss_environmental,
                    :cvss_modified_impact => @finding.cvss_modified_impact,
                    :cvss_total => @finding.cvss_total,
                    :effort => @finding.effort,
                    :type => @finding.type,
                    :overview => @finding.overview,
                    :poc => @finding.poc,
                    :remediation => @finding.remediation,
                    :approved => false,
           					:references => @finding.references,
                    :risk_cvss_v2 => @finding.risk_cvss_v2,
                    :risk_cvss_v3 => @finding.risk_cvss_v3,
                    :risk => @finding.risk
                    }

    @new_finding = TemplateFindings.new(attr)
    @new_finding.save

    redirect to("/report/#{id}/findings")
end

# Remove a finding from the report
get '/report/:id/findings/:finding_id/remove' do
    # Check for kosher name in report name
    id = params[:id]

    # Query for the report
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    finding_id = params[:finding_id]

    # Query for all Findings
    @finding = Findings.first(:report_id => id, :id => finding_id)

    if @finding == nil
        return "No Such Finding"
    end

    # Update the finding with templated finding stuff
    @finding.destroy

    redirect to("/report/#{id}/findings")
end

# preview a finding
get '/report/:id/findings/:finding_id/preview' do
    id = params[:id]

    # Query for the report
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    # Query for the Finding
    @finding = Findings.first(:report_id => id, :id => params[:finding_id])

    if @finding == nil
        return "No Such Finding"
    end

    # this flags edited findings
    if @finding.master_id
        master = TemplateFindings.first(:id => @finding.master_id)
        @finding.overview = compare_text(@finding.overview, master.overview)
    end

    ## We have to do some hackery here for wordml
    findings_xml = ""
    findings_xml << "<findings_list>"
    findings_xml << @finding.to_xml
    findings_xml << "</findings_list>"

    findings_xml = meta_markup_unencode(findings_xml, @report.short_company_name)

    report_xml = "#{findings_xml}"

	xslt_elem = Xslt.first(:finding_template => true)

	if xslt_elem

		# Push the finding from XML to XSLT
		xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

		docx_xml = xslt.transform(Nokogiri::XML(report_xml))

		# We use a temporary file with a random name
		rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

		# Create a temporary copy of the finding_template
		FileUtils::copy_file(xslt_elem.docx_location,rand_file)

		### IMAGE INSERT CODE
		if docx_xml.to_s =~ /\[!!/
			# first we read in the current [Content_Types.xml]
			content_types = ""
			Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
				zipfile.fopen("[Content_Types].xml") do |f|
					content_types = f.read # read entry content
				end
			end

			# add the png and jpg handling to end of content types document
			if !(content_types =~ /image\/jpg/)
				content_types = content_types.sub("</Types>","<Default Extension=\"jpg\" ContentType=\"image/jpg\"/></Types>")
			end
			if !(content_types =~ /image\/png/)
				content_types = content_types.sub("</Types>","<Default Extension=\"png\" ContentType=\"image/png\"/></Types>")
			end
			if !(content_types =~ /image\/jpeg/)
				content_types = content_types.sub("</Types>","<Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/></Types>")
			end

			# replace the content types to support images
			Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
				 zipfile.add_or_replace_buffer("[Content_Types].xml",
				   content_types)
			end

			# replace all [!! image !!] in the document
			imgs = docx_xml.to_s.split("[!!")
			docx = imgs.first
			imgs.delete_at(0)

			imgs.each do |image_i|

				name = image_i.split("!!]").first.gsub(" ","")
				end_xml = image_i.split("!!]").last

				# search for the image in the attachments
				image = Attachments.first(:description => name, :report_id => id)

				# tries to prevent breakage in the case image dne
				if image
					# inserts the image into the doc
					docx = image_insert(docx, rand_file, image, end_xml)
				else
					docx << end_xml
				end

			end

		else
			# no images in finding
			docx = docx_xml.to_s
		end
		#### END IMAGE INSERT CODE

		# A better way would be to create the zip file in memory and return to the user, this is not ideal
		Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
			 zipfile.add_or_replace_buffer('word/document.xml',
				 docx)
		end
		send_file rand_file, :type => 'docx', :filename => "#{@finding.title}.docx"

	else

		"You don't have a Finding Template (did you delete the default one?) -_- ... If you're an admin go to <a href='/admin/templates/add'>here</a> to add one."

	end
end

# Generate the report
get '/report/:id/generate' do
    id = params[:id]

    # Query for the report
    @report = get_report(id)

    if @report == nil
        return "No Such Report"
    end

    user = User.first(:username => get_username)

    if user
        @report.consultant_name = user.consultant_name
        @report.consultant_phone = user.consultant_phone
        @report.consultant_email = user.consultant_email
        @report.consultant_title = user.consultant_title
    else
        @report.consultant_name = ""
        @report.consultant_phone = ""
        @report.consultant_email = ""
        @report.consultant_title = ""
    end
    @report.save

    # Query for the findings that match the report_id
    if(config_options["dread"])
        @findings = Findings.all(:report_id => id, :order => [:dread_total.desc])
    elsif(config_options["cvss"])
        @findings = Findings.all(:report_id => id, :order => [:cvss_total.desc])
    else
        @findings = Findings.all(:report_id => id, :order => [:risk.desc])
    end

    ## We have to do some hackery here for wordml
    findings_xml = ""
    findings_xml << "<findings_list>"

    @findings.each do |finding|

        # This flags new or edited findings
        if finding.master_id
            master = TemplateFindings.first(:id => finding.master_id)
            if master
                finding.overview = compare_text(finding.overview, master.overview)
                finding.remediation = compare_text(finding.remediation, master.remediation)
            else
                finding.overview = compare_text(finding.overview, nil)
                finding.remediation = compare_text(finding.remediation, nil)
            end
        else
            finding.overview = compare_text(finding.overview, nil)
            finding.remediation = compare_text(finding.remediation, nil)
        end
        findings_xml << finding.to_xml
    end

    findings_xml << "</findings_list>"

    # Replace the stub elements with real XML elements
    findings_xml = meta_markup_unencode(findings_xml, @report.short_company_name)

	# check if the report has user_defined variables
	if @report.user_defined_variables

		# we need the user defined variables in xml
		udv_hash = JSON.parse(@report.user_defined_variables)
		udv = "<udv>"
		udv_hash.each do |key,value|
			udv << "<#{key}>"
			udv << "#{value}"
			udv << "</#{key}>\n"
		end
		udv << "</udv>"
	else
		udv = ""
	end

    report_xml = "<report>#{@report.to_xml}#{udv}#{findings_xml}</report>"

	xslt_elem = Xslt.first(:report_type => @report.report_type)

    # Push the finding from XML to XSLT
    xslt = Nokogiri::XSLT(File.read(xslt_elem.xslt_location))

    docx_xml = xslt.transform(Nokogiri::XML(report_xml))

    # We use a temporary file with a random name
    rand_file = "./tmp/#{rand(36**12).to_s(36)}.docx"

    # Create a temporary copy of the word doc
    FileUtils::copy_file(xslt_elem.docx_location,rand_file)

	### IMAGE INSERT CODE
	if docx_xml.to_s =~ /\[!!/
		# first we read in the current [Content_Types.xml]
		content_types = ""
		Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
			zipfile.fopen("[Content_Types].xml") do |f|
				content_types = f.read # read entry content
			end
		end

		# add the png and jpg handling to end of content types document
		if !(content_types =~ /image\/jpg/)
			content_types = content_types.sub("</Types>","<Default Extension=\"jpg\" ContentType=\"image/jpg\"/></Types>")
		end
		if !(content_types =~ /image\/png/)
			content_types = content_types.sub("</Types>","<Default Extension=\"png\" ContentType=\"image/png\"/></Types>")
		end
		if !(content_types =~ /image\/jpeg/)
			content_types = content_types.sub("</Types>","<Default Extension=\"jpeg\" ContentType=\"image/jpeg\"/></Types>")
		end

		# replace the content types to support images
		Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
			 zipfile.add_or_replace_buffer("[Content_Types].xml",
			   content_types)
		end

		# replace all [!! image !!] in the document
		imgs = docx_xml.to_s.split("[!!")
		docx = imgs.first
		imgs.delete_at(0)

		imgs.each do |image_i|

			name = image_i.split("!!]").first.gsub(" ","")
			end_xml = image_i.split("!!]").last

			# search for the image in the attachments
			image = Attachments.first(:description => name, :report_id => id)

				# tries to prevent breakage in the case image dne
				if image
					# inserts the image
					docx = image_insert(docx, rand_file, image, end_xml)
				else
					docx << end_xml
				end

		end
	else
		# no images in finding
		docx = docx_xml.to_s
	end
	#### END IMAGE INSERT CODE

    # Create the docx, would be better to create the zip file in memory and return to the user
    Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
         zipfile.add_or_replace_buffer('word/document.xml',
           docx)
    end

    send_file rand_file, :type => 'docx', :filename => "#{@report.report_name}.docx"
end

# Export a report
get '/report/:id/export' do
	json = {}

    id = params[:id]
	report = get_report(id)

	# bail without a report
	redirect to("/") unless report

	# add the report
	json["report"] = report

	# add the findings
    findings = Findings.all(:report_id => id)
	json["findings"] = findings

	local_filename = "./tmp/#{rand(36**12).to_s(36)}.json"
    File.open(local_filename, 'w') {|f| f.write(JSON.pretty_generate(json)) }

	send_file local_filename, :type => 'json', :filename => "exported_report.json"
end

# Import a report
get '/report/import' do
	haml :import_report
end

# Import a report
post '/report/import' do
	# reject if the file is above a certain limit
	if params[:file][:tempfile].size > 1000000
		return "File too large. 1MB limit"
	end

	json_file = params[:file][:tempfile].read
	line = JSON.parse(json_file)

	line["report"]["id"] = nil

	f = Reports.create(line["report"])
	f.save

	# now add the findings
	line["findings"].each do |finding|
		finding["id"] = nil
		finding["master_id"] = nil
		finding["report_id"] = f.id
		finding["finding_modified"] = nil

        finding["dread_total"] = 0 if finding["dread_total"] == nil
        finding["cvss_total"] = 0 if finding["cvss_total"] == nil
        finding["risk"] = 1 if finding["risk"] == nil

		g = Findings.create(finding)
		g.save
	end

	# we should redirect to the newly imported report
	redirect to("/report/#{f.id}/edit")
end

get '/report/:id/text_status' do
    id = params[:id]
	@report = get_report(id)

	# bail without a report
	redirect to("/") unless @report

	# add the findings
    @findings = Findings.all(:report_id => id)

	haml :text_status, :encode_html => true
end

# generate an asciidoc version of current findings
get '/report/:id/asciidoc_status' do
    id = params[:id]
	report = get_report(id)

	# bail without a report
	redirect to("/") unless report

	# add the findings
    findings = Findings.all(:report_id => id)

	ascii_doc_ = ""
	findings.each do |finding|
		ascii_doc_ << gen_asciidoc(finding,config_options["dread"])
	end

	local_filename = "./tmp/#{rand(36**12).to_s(36)}.asd"
    File.open(local_filename, 'w') {|f| f.write(ascii_doc_) }

	send_file local_filename, :type => 'txt', :filename => "report_#{id}_findings.asd"
end

# generate a presentation of current report
get '/report/:id/presentation' do
    # check the user has installed reveal
    if !(File.directory?(Dir.pwd+"/public/reveal.js"))
        return "reveal.js not found in /public/ directory. To install:<br><br> 1. Goto [INSTALL_DIR]/public/ <br>2.run 'git clone https://github.com/hakimel/reveal.js.git'<br>3. Restart Serpico"
    end

    id = params[:id]

    @report = get_report(id)

    # bail without a report
    redirect to("/") unless @report

    # add the findings
    @findings = Findings.all(:report_id => id)

    @dread = config_options["dread"]
    @cvss = config_options["cvss"]

    haml :presentation, :encode_html => true, :layout => false
end


# Helper Functions

# Return if the user has a valid session or not
def valid_session?
    return Sessions.is_valid?(session[:session_id])
end

# Get the current users type
def user_type
    return Sessions.type(session[:session_id])
end

# Get the current users, username
def get_username
    return Sessions.get_username(session[:session_id])
end

# Check if the user is an administrator
def is_administrator?
    return true if Sessions.type(session[:session_id]) == "Administrator"
end

# Grab a specific report
def get_report(id)
    if is_administrator?
        return Reports.first(:id => id)
    else
        report = Reports.first(:id => id)
        if report
            authors = report.authors
            return report if report.owner == get_username
            if authors
                return report if authors.include?(get_username)
            end
        end
    end
end

# List out the reports
def get_reports
    if is_administrator?
        return Reports.all
    else
        reports = Reports.all
        reports_array = []
        reports.each do |report|
            next unless report and get_username
            authors = report.authors
            reports_array.push(report) if report.owner == get_username
            if authors
                reports_array.push(report) if authors.include?(get_username)
            end
        end
        return nil unless reports_array
        return reports_array
    end
end
#<hadhemi
def findings_by_severity(findings)
sum=[]
none=0
low=0
medium=0
high=0
critical=0


findings.each do |finding|
 if finding.risk==0
   none=none+1
 elsif finding.risk==1
   low=low+1
 elsif finding.risk==2
   medium=medium+1
 elsif finding.risk==3
   high=high+1
 else
   critical=critical+1
 end

end
sum.push(none,low,medium,high,critical)
return sum

end

#>hadhemi

#<hadhemi
def findings_by_type(findings)
types=["Web Application","Network Services", "Best Practice", "Compliance", "Database", "Network Internal", "Router Configuration","Social Engineering", "Physical", "Wireless", "Network Security", "System Security", "Logging and Auditing"]
stats=[]
types.each do |type|
  a=0
 findings.each do |finding|
   if finding.type==type
     a=a+1
   end
 end
stats.push(a)
end

return stats

end
#>hadhemi

#<hadhemi
def findings_number(findings)
  a=0
 findings.each do |finding|
     a=a+1
   end
return a
end
#>hadhemi

#<hadhemi
def findings_by_auth(findings)
auth=["Anonymos Remote","Anonymos Local","Authenticated Remote","Authenticated Local"]
res=[]
a=0
b=0
c=0
d=0
a1=0
b1=0
c1=0
d1=0
 findings.each do |finding|
   if finding.au2=="None"
     if finding.av2=="Local" or finding.av2=="Adjacent Network"
       b=b+1
     elsif finding.av2=="Network"
       a=a+1
     end
   elsif finding.au2=="Multiple" or finding.au2=="Single"
     if finding.av2=="Local" or finding.av2=="Adjacent Network"
       d=d+1
     elsif finding.av2=="Network"
       c=c+1
     end
   end

   if finding.pr=="None"
     if finding.av=="Local" or finding.av=="Adjacent Network" or finding.av=="Physical"
       b1=b1+1
     elsif finding.av=="Network"
       a1=a1+1
     end
   elsif finding.pr=="Low" or finding.pr=="High"
     if finding.av=="Local" or finding.av=="Adjacent Network" or finding.av=="Physical"
       d1=d1+1
     elsif finding.av=="Network"
       c1=c1+1
     end
   end
 end
res.push(a,b,c,d,a1,b1,c1,d1)

return res

end
#>hadhemi


#<hadhemi
def get_reports_by_type
    if is_administrator?
      reports=Reports.all
      stats_array = []
      types=['External', 'Internal', 'Wireless', 'Web App', 'Internal/External']

      types.each do |type|
        a=0
        reports.each do |report|

          d=report.Rtype
          if d==type
            a=a+1
          end

        end
        stats_array.push(a)
      end
      return stats_array
    else
        reports = Reports.all
        reports_array = []
        reports.each do |report|
            next unless report and get_username
            authors = report.authors
            reports_array.push(report) if report.owner == get_username
            if authors
                reports_array.push(report) if authors.include?(get_username)
            end
        end
        return nil unless reports_array
        #return reports_array
        stats_array = []
        types=['External', 'Internal', 'Wireless', 'Web App', 'Internal/External']

        types.each do |type|
          a=0
          reports_array.each do |reportA|
            d=reportA.Rtype
            if d==type
              a=a+1
            end

          end
          stats_array.push(a)
        end
        return stats_array
    end
end
#>hadhemi

#<hadhemi
def get_reports_per_month

  if is_administrator?
    reports=Reports.all
    stats_array = []
    monthes=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

    monthes.each do |month|
      #have to be a=0 remember to fix it
      a=0
      reports.each do |report|
        d=report.date.split("/").map(&:to_i)
        if d[0] == month
          a=a+1
        end
      end
      stats_array.push(a)
    end
    return stats_array
  else
      reports = Reports.all
      reports_array = []
      reports.each do |report|
          next unless report and get_username
          authors = report.authors
          reports_array.push(report) if report.owner == get_username
          if authors
              reports_array.push(report) if authors.include?(get_username)
          end
      end
      return nil unless reports_array
      #return reports_array

      stats_array = []
      monthes=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]

      monthes.each do |month|
        #have to be a=0 remember to fix it
        a=0
        reports_array.each do |reportA|
          d=reportA.date.split("/").map(&:to_i)
          if d[0] == month
            a=a+1
          end
        end
        stats_array.push(a)
      end
      return stats_array
  end
end
#>hadhemi

#<hadhemi
def get_reports_by_client
    if is_administrator?
        reports= Reports.all

        stat=Hash.new(0)

        reports.each { |report| stat[report.full_company_name.downcase] += 1 }


        return stat
    else
        reports = Reports.all
        reports_array = []
        reports.each do |report|
            next unless report and get_username
            authors = report.authors
            reports_array.push(report) if report.owner == get_username
            if authors
                reports_array.push(report) if authors.include?(get_username)
            end
        end
        return nil unless reports_array
        #return reports_array

        stat=Hash.new(0)

        reports_array.each { |reportA| stat[reportA.full_company_name.downcase] += 1 }

        return stat
    end
end
#>hadhemi





def image_insert(docx, rand_file, image, end_xml)
	# assign random id, ms requires it begin with a letter. weird.
	p_id = "d#{rand(36**7).to_s(36)}"
	name = image.description

	# insert picture into xml
	docx << " <w:pict><v:shape id=\"myShape_#{p_id}\" type=\"#_x0000_t75\" style=\"width:400; height:200\"><v:imagedata r:id=\"#{p_id}\"/></v:shape></w:pict>"
	docx << end_xml

	# insert picture into zip
	exists = false
	img_data = ""

	File.open(image.filename_location, 'rb') {|file| img_data << file.read }
	Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
		#iterate zipfile to see if it has media dir, this could be better
		zipfile.each do	|file|
			if file.name =~ /word\/media/
				exists = true
			end
		end

		if exists
			zipfile.add_or_replace_buffer("word/media/#{name}",img_data)
		else
			zipfile.add_or_replace_buffer("word/#{name}",img_data)
		end
	end

	# update document.xml.rels
	docu_rels = ""
	Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
		zipfile.fopen("word/_rels/document.xml.rels") do |f|
			docu_rels = f.read # read entry content
		end
	end

	if exists
		docu_rels = docu_rels.sub("</Relationships>","<Relationship Id=\"#{p_id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"media/#{name}\"/></Relationships>")
	else
		docu_rels = docu_rels.sub("</Relationships>","<Relationship Id=\"#{p_id}\" Type=\"http://schemas.openxmlformats.org/officeDocument/2006/relationships/image\" Target=\"#{name}\"/></Relationships>")
	end

	Zip::Archive.open(rand_file, Zip::CREATE) do |zipfile|
		zipfile.add_or_replace_buffer("word/_rels/document.xml.rels",
			docu_rels)
	end

	return docx
end
