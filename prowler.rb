#!/usr/bin/ruby
require "rubygems"
require "bundler/setup"

require 'net/http'
require 'net/https'
require 'uri'
require 'json'
require "getopt/long"
require 'prowl'

opt = Getopt::Long.getopts(
  ["--email", "-e",     Getopt::REQUIRED],
  ["--password", "-p",  Getopt::REQUIRED],
  ["--apikey", "-a",    Getopt::REQUIRED]
)

email = opt['email']    || ENV['IRCCLOUD_EMAIL']
pass  = opt['password'] || ENV['IRCCLOUD_PASS']
api   = opt['apikey']   || ENV['PROWL_APIKEY']

#TODO Make this configurable
ignorednicks = ["github"]
ignoredstrings = [/Capistrano: marten is deploying/]

if !email or !pass or !api then
  puts 'Usage: ' + $0 + ' --email <you@example.com> --password <your_password> --apikey <prowl_api_key>'
  puts
  puts "You can create a Prowl API key here: https://www.prowlapp.com/api_settings.php"
  exit
end

prowl = Prowl.new(:apikey => api, :application => "IrcCloud Prowler")
raise "Sorry, the Prowl API key is not valid." unless prowl.valid?

uri_login  = URI.parse('https://irccloud.com/chat/login')
uri_stream = URI.parse('https://irccloud.com/chat/stream')

# do login to get session cookie:
puts 'Logging in...'
req = Net::HTTP::Post.new(uri_login.path)
req.set_form_data({'email' => email, 'password' => pass })
http = Net::HTTP.new(uri_login.host, uri_login.port)
http.use_ssl = true
res = http.start {|http| http.request(req) } 
case res
when Net::HTTPSuccess, Net::HTTPRedirection
  session = res.response['set-cookie'].split(';')[0]
  puts 'Session: ' + session
else
  res.error!
end

eob     = {}
servers = {}
buffers = {}
buffer  = ''
# start stream
http = Net::HTTP.new(uri_stream.host, uri_stream.port)
http.use_ssl = true
http.request_get(uri_stream.path, {'cookie'=>session}) {|response|
  p response['content-type']
  response.read_body do |str|
    buffer += str
    lines = buffer.split("\n")
    lines.each { |line|
      begin
        puts line

        ev = JSON.parse line

        if ev['highlight'] == true
          # {"bid":83392,
          # "eid":10,
          # "type":"buffer_msg",
          # "time":1314296055,
          # "highlight":true,
          # "from":"marten_",
          # "msg":"marten: ping!",
          # "chan":"#test",
          # "cid":8643}
          next if ignorednicks.include?(ev["from"])
          next if ignoredstrings.find {|regex| ev["msg"] =~ regex }
          puts "PROWLED"
          prowl.add(:event => "Highlight", :description => "#{ev["chan"]} <#{ev['from']}> #{ev['msg']}")
        end
      rescue JSON::JSONError => e
        buffer = line
        next
      end
    }
    buffer = ''
  end
}
