require 'sinatra'
require 'sinatra/activerecord'
require 'sinatra/namespace'


module Dorothy
  class DoroGUI < Sinatra::Base
    register Sinatra::Namespace


    conf = "#{File.expand_path("~")}/.dorothy.yml"

    #LOAD ENV
    if Util.exists?(conf)
      DoroSettings.load!(conf)
    else
      DoroConfig.create
      exit(0)
    end

#    configure :production, :development do
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
      erb :analyses
    end

    get '/queue' do
      @title = "Queue Status"
      @queue = AnalysisQueue.all.order(id: :asc, priority: :desc)
      @analyses = Analyses.all
      erb :queue
    end

    get '/configure' do
      @title = "Configure"

      erb :configure
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



    get '/sys_procs/:analid' do
      @title = "System Processes Spowned"
      @sys_procs = SystemProcs.where(:analysis_id => params[:analid])
      erb :sys_procs
    end

    namespace '/net' do

      namespace '/:dump_sha1' do

        get '/' do
          @title = "Network Flows"
          @net_dumps = TrafficDumps.where(:sha256 => params[:dump_sha1])
          @flows= Flows.where(:traffic_dump => params[:dump_sha1])

          erb :flows
        end


        get '/flow/:flow_id' do
          @net_dumps = TrafficDumps.where(:sha256 => params[:dump_sha1])
          @pcapr = Doroxtractr.create "http://#{DoroSettings.pcapr[:host]}:#{DoroSettings.pcapr[:port]}/pcaps/1/pcap/#{@net_dumps.first.pcapr_id}"
          @flow_cont = @pcapr.flowcontent(params[:flow_id])
          @flow_pkts = @pcapr.flows("#{params[:flow_id]}").first
          @cont = ""
          @pcapr.flows("#{params[:flow_id]}").first.each  do |pkt|
            @cont << pkt.payload
          end


          erb :flows_pcapr
        end

      end
    end


    get '/resume/:analid' do
      @title = "Sample Analysis Resume"
      @analysis_dir = DoroSettings.env[:analysis_dir]
      @analid = params[:analid]
      @sample = Samples.where(:sha256 => Analyses.where(:id => @analid).first.sample).first
      @sys_procs = SystemProcs.where(:analysis_id => params[:analid])
      @malware = Malwares.where(:bin => Analyses.where(:id => @analid).first.sample).first
      @sophos = @malware.nil? ? nil : AvSigns.where(:id => @malware.id).where(:av_name => 'Sophos').first

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

    get '/upload' do
      @sandboxes = Sandboxes.all
      erb :upload
    end

    post '/upload' do
      localpath = sources["webgui"]["localdir"] + "/#{params[:uploaded_data][:filename]}"
      FileUtils.mv(params[:uploaded_data][:tempfile].path, localpath) unless params[:uploaded_data].nil?
      id = QueueManager.add(localpath,5, "webgui", params[:OS], params[:priority])


      #entry = AnalysisQueue.create(date: get_time, binary: localpath, filename: filename, source: "webgui", priority: params[:priority], profile: params[:OS], user: "webuser")
      #entry.save
      #Date	Filename	Source	Priority	User	Analysed?
      erb "Upload Complete. Prio #{params[:priority]} - OS #{params[:OS]} - Scheduled with Queue ID #{id}"
    end

    after do
      ActiveRecord::Base.connection.close
    end

  end

end
