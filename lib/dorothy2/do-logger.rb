# Copyright (C) 2013 marco riccardi.
# This file is part of Dorothy - http://www.honeynet.it/dorothy
# See the file 'LICENSE' for copying permission.

module Dorothy
#The original Logger has a little bug that prevent me to add the progname while using warn,error,etc methods
class DoroLogger < Logger
  def initialize(logdev, shift_age = 0, shift_size = 1048576)
    super(logdev, shift_age, shift_size)
    @formatter = proc do |severity, datetime, progname, msg|
      "[#{datetime.strftime('%d/%m/%Y %H:%M:%S')}] #{severity =~ /ERROR|FATAL/ ? severity.red : severity} [#{progname.yellow}] #{msg}\n"
    end
  end

  def debug(progname, text, &block)
    add(DEBUG, text, progname, &block)
  end

  def warn(progname, text, &block)
    add(WARN, text, progname, &block)
  end

  def error(progname, text, &block)
    add(ERROR, text, progname, &block)
  end

  def fatal(progname, text, &block)
    add(FATAL, text, progname, &block)
  end

  def info(progname, text, &block)
    add(INFO, text, progname, &block)
  end
end

end