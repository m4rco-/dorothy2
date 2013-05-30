require 'rubygems'
require "test/unit"
require 'dorothy2'          #comment for testing/developmnet

#load '../lib/dorothy2.rb'

include Dorothy

LOGGER = DoroLogger.new(STDOUT, "weekly")

CONF = "#{File.expand_path("~")}/.dorothy.yml"

#LOAD ENV
if Util.exists?(CONF)
  DoroSettings.load!(CONF)
else
  DoroConfig.create
  exit(0)
end

class DoroTest < Test::Unit::TestCase

  # Called before every test method runs. Can be used
  # to set up fixture information.
  def setup
    DoroSettings.load!(CONF)
     @db = Insertdb.new
     guestvm = @db.find_vm
     assert_nothing_raised { @vsm = Doro_VSM::ESX.new(DoroSettings.esx[:host],DoroSettings.esx[:user],DoroSettings.esx[:pass],guestvm[1], guestvm[3], guestvm[4]) }
     @nam = Doro_NAM.new(DoroSettings.nam)
  end

  # Called after every test method runs. Can be used to tear
  # down fixture information.

  def teardown
    @db.vm_init
    @db.close
  end

  # Fake test
  def test_db_A_connection
    assert_kind_of(Dorothy::Insertdb, @db, "Problem, can't connect to DB")
  end

  def test_db_B_insert
    randstring = (0...8).map{(65+rand(26)).chr}.join
    values = [randstring, 16, "pe", "", "test.exe", "testtest", "test"]
    assert_kind_of(PG::Result, @db.insert("samples", values), "Problem, can't insert data into the DB")
  end

#  def test_vsm
#    guestvm = @db.find_vm
#    assert_nothing_raised { @vsm = Doro_VSM::ESX.new(DoroSettings.esx[:host],DoroSettings.esx[:user],DoroSettings.esx[:pass],guestvm[1], guestvm[3], guestvm[4]) }
#  end

  def test_vsm_A_execute
    assert_nothing_raised {@vsm.exec_file("windows\\system32\\calc.exe")}
    assert_kind_of(Fixnum, @vsm.exec_file("windows\\system32\\calc.exe"))
  end

  def test_vsm_B_chk_internet
    assert_nothing_raised {@vsm.check_internet}
  end

  def test_vsm_C_screenshot
    assert_nothing_raised {@vsm.screenshot}
  end

  def test_vsm_D_copy_screenshot
    screen = @vsm.screenshot
    assert_nothing_raised {Ssh.download(DoroSettings.esx[:host],DoroSettings.esx[:user], DoroSettings.esx[:pass], screen, Dir.pwd)}
  end

  def test_vsm_E_revertvm
    assert_nothing_raised {@vsm.revert_vm}
  end

  #NAM

  def test_nam_A_start_stop
    puts "NAM".yellow + " Starting sniffer on NAM"
    assert_nothing_raised { @nampid = @nam.start_sniffer("localhost",DoroSettings.nam[:interface], "testpcap", DoroSettings.nam[:pcaphome])}
    assert_kind_of(Fixnum, @nampid)
    sleep 3
    puts "NAM".yellow + " Stopping sniffer on NAM"
    assert_nothing_raised {@nam.stop_sniffer(@nampid)}
  end

  def test_nam_C_copydump
    assert_nothing_raised {Ssh.download(DoroSettings.nam[:host], DoroSettings.nam[:user],DoroSettings.nam[:pass], DoroSettings.nam[:pcaphome] + "/" + "testpcap.pcap", Dir.pwd)}
  end


end