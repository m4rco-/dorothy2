module Process
  #  Supply daemon for pre ruby 1.9
  #  Adapted from lib/active_support/core_ext/process/daemon.rb
  def self.daemon(nochdir = nil, noclose = nil)
    exit! if fork                     # Parent exits, child continues.
    Process.setsid                    # Become session leader.
    exit! if fork                     # Zap session leader. See [1].

    unless nochdir
      Dir.chdir "/"                 # Release old working directory.
    end

    unless noclose
      STDIN.reopen "/dev/null"       # Free file descriptors and
      STDOUT.reopen "/dev/null", "a" # point them somewhere sensible.
      STDERR.reopen '/dev/null', 'a'
    end

    trap("TERM") { exit }

    return 0

  end unless self.respond_to? :daemon
end

module Dorothy
  ROOT = File.expand_path(File.dirname(File.dirname(__FILE__)))
  $: << ROOT
end
