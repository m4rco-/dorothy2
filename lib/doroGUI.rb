require 'sinatra'
require 'sinatra/activerecord'
require 'sinatra/namespace'


module Dorothy
  class DoroGUI < Sinatra::Base
    register Sinatra::Namespace

    enable :logging, :dump_errors
    file = File.new(DoroSettings.wgui[:logfile], 'a+')
    file.sync = true
    use Rack::CommonLogger, file
    before { env['rack.errors'] = file  }

    set :app_file, __FILE__
    root = File.expand_path(File.dirname(__FILE__))
    set :public_folder, File.join(root, 'www/public')
    set :views, Proc.new { File.join(root, 'www/views') }


    ActiveRecord::Base.establish_connection(
        adapter:    'postgresql',
        host:       DoroSettings.dorothive[:dbhost],
        database:   DoroSettings.dorothive[:dbname],
        username:   DoroSettings.dorothive[:dbuser],
        password:   DoroSettings.dorothive[:dbpass],
        port:       5432,
        schema_search_path: 'dorothy' )

    sources = YAML.load_file(DoroSettings.env[:home] + '/etc/sources.yml')


    class Analyses < ActiveRecord::Base
      self.table_name = "analyses"
    end

    class Samples < ActiveRecord::Base
      self.table_name = "samples"
    end

    class Flows < ActiveRecord::Base
      self.table_name = "flows"
    end

    class Sandboxes < ActiveRecord::Base
      self.table_name = "sandboxes"
    end

    class AnalysisQueue < ActiveRecord::Base
      self.table_name = "analysis_queue"
    end

    class TrafficDumps < ActiveRecord::Base
      self.table_name = "traffic_dumps"
    end

    class Sources < ActiveRecord::Base
      self.table_name = "sources"
    end

    class Emails < ActiveRecord::Base
      self.table_name = "emails"
    end

    class Receivers < ActiveRecord::Base
      self.table_name = "email_receivers"
    end

    class Sightings < ActiveRecord::Base
      self.table_name = "sightings"
    end

    class SystemProcs < ActiveRecord::Base
      self.table_name = "sys_procs"
    end

    class Malwares < ActiveRecord::Base
      self.table_name = "malwares"
    end

    class AvSigns < ActiveRecord::Base
      self.table_name = "av_signs"
    end

    get '/' do
      @title = "Analyses"
      @analyses = Analyses.all
      @samples  = Samples.all
      @queue = AnalysisQueue.all
      @sightings = Sightings.all
      @emails = Emails.all



      erb :analyses
    end



    get '/queue' do
      @title = "Queue Status"
      @queue = AnalysisQueue.all.order(id: :asc, priority: :desc)
      @sources = Sources.all
      @analyses = Analyses.all
      @emails = Emails.all
      erb :queue
    end


    get '/resume/:analid' do
      @title = "Sample Analysis Resume"
      @analysis_dir = DoroSettings.env[:analysis_dir]
      @analid = params[:analid]
      @sample = Samples.where(:sha256 => Analyses.where(:id => @analid).first.sample).first
      @sys_procs = SystemProcs.where(:analysis_id => params[:analid])
      @malware = Malwares.where(:bin => Analyses.where(:id => @analid).first.sample).first
      @sophos = @malware.nil? ? nil : AvSigns.where(:id => @malware.id).where(:av_name => 'Sophos').first

      @mailid = Sightings.where(:id => AnalysisQueue.where( :id => Analyses.where(:id => @analid).first.queue_id).first.sighting).first.src_email



      @net_dumps = TrafficDumps.where(:sha256 => Analyses.where(:id => @analid).first.traffic_dump)
      @flows= Flows.where(:traffic_dump => Analyses.where(:id => @analid).first.traffic_dump)

      @imgs = []
      Dir[DoroSettings.env[:analysis_dir] + "/#{@analid}/screens/*.png"].each  {|file| @imgs.push(File.basename(file))  }

      erb :resume
    end

    get '/screens/:analid/:name' do
      full_path = DoroSettings.env[:analysis_dir] + "/" + params[:analid] + "/screens/" + params[:name]
      send_file full_path.strip, :filename => params[:name].strip, :disposition => 'inline'
    end


    get '/profile/:profile' do
      @profile = Util.load_profile(params[:profile])

      erb :profile
    end


    get '/upload' do
      @sandboxes = Sandboxes.all
      @profiles = YAML.load_file(DoroSettings.env[:home] + '/etc/profiles.yml')

      erb :upload
    end

    post '/upload' do
      localpath = sources["webgui"]["localdir"] + "/#{params[:uploaded_data][:filename]}"
      FileUtils.mv(params[:uploaded_data][:tempfile].path, localpath) unless params[:uploaded_data].nil?
      id = QueueManager.add(localpath, 'webgui', params[:profile], params[:priority])

      #entry = AnalysisQueue.create(date: get_time, binary: localpath, filename: filename, source: "webgui", priority: params[:priority], profile: params[:OS], user: "webuser")
      #entry.save
      erb "Upload Complete. Prio #{params[:priority]} - OS #{params[:OS]} - Scheduled with Queue ID #{id}"
    end



    namespace '/email' do
      get '/view/:mail_id' do
        @email = Emails.where(:id => params[:mail_id]).first
        @receivers = Receivers.where(:email_id => params[:mail_id])
        erb :email
      end

      get '/download/:mail_id' do
        email = Emails.where(:id => params[:mail_id]).first

        content_type 'Application/octet-stream'
        attachment( "Message_#{email.id}" + '.eml')
        PG::Connection.unescape_bytea(email.data)
      end

    end



    namespace '/samples/' do

      get '/' do
        @title = "Sample Information"
        @samples  = Samples.all
        erb :samples
      end

      get ':sha256' do |sha256|
        @samples = Samples.where(:sha256 => params[:sha256])

        #list all the analysis that have been done on this file , including timestamp, OS, etc
        erb :samples
      end


      get 'download/:sha256' do |sha256|
        first_id = Analyses.where(:sample => params[:sha256]).first.id
        filename = Samples.where(:sha256 => params[:sha256]).first.filename
        full_path = DoroSettings.env[:analysis_dir] + "/#{first_id}/bin/" + filename
        send_file full_path.strip, :filename => filename, :type => 'Application/octet-stream'
      end

    end


    namespace '/net' do

      namespace '/:dump_sha1' do

        get '/' do
          @title = "Network Flows"
          @net_dumps = TrafficDumps.where(:sha256 => params[:dump_sha1])
          @flows= Flows.where(:traffic_dump => params[:dump_sha1])

          erb :flows
        end

      end
    end


    after do
      ActiveRecord::Base.connection.close
    end

  end

end
