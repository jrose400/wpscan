#!/usr/bin/env ruby

#--
# WPScan - WordPress Security Scanner
# Copyright (C) 2012
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#++

$: << '.'
require File.dirname(__FILE__) +'/lib/wpscan/wpscan_helper'
require 'log4r'
require 'log4r/configurator'
include Log4r

banner()

begin
  wpscan_options = WpscanOptions.load_from_arguments

  unless wpscan_options.has_options?
    raise "No argument supplied\n#{usage()}"
  end

  if wpscan_options.help
    help()
    exit
  end

  # Output logging
  Configurator.custom_levels('ERROR','VULN', 'WARN', 'INFO')
  log = Log4r::Logger.new('logtest')

  if wpscan_options.logfile
    output_file = wpscan_options.logfile
    file = FileOutputter.new('fileOutputter', :filename => output_file,:trunc => false)
    log.add(file)
    
    pf = PatternFormatter.new(:pattern => "%d %l %m")
    file.formatter = pf
    puts "Report saved to '#{wpscan_options.logfile}'"
  else
    screen = Outputter.stdout
    pf = PatternFormatter.new(:pattern => "%l %m")
    screen.formatter = pf
    log.outputters = screen
  end

  # Check for updates
  if wpscan_options.update
    unless @updater.nil?
      puts @updater.update()
    else
      puts "Svn / Git not installed, or wpscan has not been installed with one of them."
      puts "Update aborted"
    end
    exit(1)
  end

  wp_target = WpTarget.new(wpscan_options.url, wpscan_options.to_h)

  # Remote website up?
  unless wp_target.is_online?
    raise "The WordPress URL supplied '#{wp_target.uri}' seems to be down."
  end

  redirection = wp_target.redirection
  if redirection
    if wpscan_options.follow_redirection
      puts "Following redirection #{redirection}"
      puts
    else
      puts "The remote host tried to redirect us to #{redirection}"
      puts "Do you want follow the redirection ? [y/n]"
    end

    if wpscan_options.follow_redirection or Readline.readline =~ /^y/i
      wpscan_options.url = redirection
      wp_target = WpTarget.new(redirection, wpscan_options.to_h)
    else
      puts "Scan aborted"
      exit
    end
  end


  # Remote website is wordpress?
  unless wpscan_options.force
    unless wp_target.is_wordpress?
      raise "The remote website is up, but does not seem to be running WordPress."
    end
  end

  unless wp_target.wp_content_dir
    raise "The wp_content_dir has not been found, please supply it with --wp-content-dir"
  end

  unless wp_target.wp_plugins_dir_exists?
    puts "The plugins directory '#{wp_target.wp_plugins_dir}' does not exist."
    puts "You can specify one per command line option (don't forget to include the wp-content directory if needed)"
    puts "Continue? [y/n]"
    unless Readline.readline =~ /^y/i
      exit
    end
  end

  # Output runtime data
  start_time = Time.now
  log.info "| URL: #{wp_target.url}"
  log.info "| Started on #{start_time.asctime}"

  wp_theme = wp_target.theme
  if wp_theme
    # Theme version is handled in wp_item.to_s
    log.info "[+] The WordPress theme in use is #{wp_theme}"

    theme_vulnerabilities = wp_theme.vulnerabilities
    unless theme_vulnerabilities.empty?
      log.vuln "[!] We have identified #{theme_vulnerabilities.size} vulnerabilities for this theme :"
      theme_vulnerabilities.each do |vulnerability|
        
        log.vuln " | * Title: #{vulnerability.title}"
        log.vuln " | * Reference: #{vulnerability.reference}"
      end
      
    end
  end

  if wp_target.has_readme?
    log.vuln "[!] The WordPress '#{wp_target.readme_url}' file exists"
  end

  if wp_target.has_full_path_disclosure?
    log.vuln "[!] Full Path Disclosure (FPD) in '#{wp_target.full_path_disclosure_url}'"
  end

  if wp_target.has_debug_log?
    log.vuln "[!] Debug log file found : #{wp_target.debug_log_url}"
  end

  wp_target.config_backup.each do |file_url|
    log.vuln "[!] A wp-config.php backup file has been found '#{file_url}'"
  end

  if wp_target.search_replace_db_2_exists?
    log.vuln "[!] searchreplacedb2.php has been found '#{wp_target.search_replace_db_2_url}'"
  end

  if wp_target.is_multisite?
    log.info "[+] This site seems to be a multisite (http://codex.wordpress.org/Glossary#Multisite)"
  end

  if wp_target.registration_enabled?
    log.info "[+] User registration is enabled"
  end

  if wp_target.has_malwares?
    malwares = wp_target.malwares
    log.vuln "[!] #{malwares.size} malware(s) found :"

    malwares.each do |malware_url|
      
      log.vuln " | #{malware_url}"
    end
  end

  wp_version = wp_target.version
  if wp_version
    log.info "[+] WordPress version #{wp_version.number} identified from #{wp_version.discovery_method}"

    version_vulnerabilities = wp_version.vulnerabilities

    unless version_vulnerabilities.empty?
      log.vuln "[!] We have identified #{version_vulnerabilities.size} vulnerabilities from the version number :"
      version_vulnerabilities.each do |vulnerability|
        log.vuln " | * Title: #{vulnerability.title}"
        log.vuln " | * Reference: #{vulnerability.reference}"
      end
    end
  end

  if wpscan_options.enumerate_plugins == nil and wpscan_options.enumerate_only_vulnerable_plugins == nil
    log.info "[+] Enumerating plugins from passive detection ... "

    plugins = wp_target.plugins_from_passive_detection(:base_url => wp_target.uri, :wp_content_dir => wp_target.wp_content_dir)
    unless plugins.empty?
      log.info "#{plugins.size} found :"

      plugins.each do |plugin|
        log.info " | Name: #{plugin.name}"
        log.info " | Location: #{plugin.get_full_url}"

        plugin.vulnerabilities.each do |vulnerability|
          log.vuln " | [!] #{vulnerability.title}"
          log.vuln " | * Reference: #{vulnerability.reference}"
        end
      end
    else
      log.info "No plugins found :("
    end
  end

  # Enumerate the installed plugins
  if wpscan_options.enumerate_plugins or wpscan_options.enumerate_only_vulnerable_plugins
    log.info "[+] Enumerating installed plugins #{'(only vulnerable ones)' if wpscan_options.enumerate_only_vulnerable_plugins} ..."

    options = {}
    options[:base_url]              = wp_target.uri
    options[:only_vulnerable_ones]  = wpscan_options.enumerate_only_vulnerable_plugins || false
    options[:show_progress_bar]     = wpscan_options.logfile ? false : true
    options[:wp_content_dir]        = wp_target.wp_content_dir
    options[:error_404_hash]        = wp_target.error_404_hash
    options[:wp_plugins_dir]        = wp_target.wp_plugins_dir

    plugins = wp_target.plugins_from_aggressive_detection(options)
    unless plugins.empty?
      log.info "[+] We found #{plugins.size.to_s} plugins:"

      plugins.each do |plugin|
        log.info " | Name: #{plugin}" #this will also output the version number if detected
        log.info " | Location: #{plugin.get_url_without_filename}"
        log.info " | Directory listing enabled: Yes" if plugin.directory_listing?
        log.info " | Readme: #{plugin.readme_url}" if plugin.has_readme?
        log.info " | Changelog: #{plugin.changelog_url}" if plugin.has_changelog?

        plugin.vulnerabilities.each do |vulnerability|
          #vulnerability['vulnerability'][0]['uri'] == nil ? "" : uri = vulnerability['vulnerability'][0]['uri'] # uri
          #vulnerability['vulnerability'][0]['postdata'] == nil ? "" : postdata = CGI.unescapeHTML(vulnerability['vulnerability'][0]['postdata']) # postdata

          log.vuln " | [!] #{vulnerability.title}"
          log.vuln " | * Reference: #{vulnerability.reference}"

          # This has been commented out as MSF are moving from
          # XML-RPC to MessagePack.
          # I need to get to grips with the new way of communicating
          # with MSF and implement new code.

          # check if vuln is exploitable
          #Exploit.new(url, type, uri, postdata.to_s, use_proxy, proxy_addr, proxy_port)
        end

        if plugin.error_log?
          log.info " | [!] A WordPress error_log file has been found : #{plugin.error_log_url}"
        end
      end
    else
      log.info "No plugins found :("
    end
  end

  # Enumerate installed themes
  if wpscan_options.enumerate_themes or wpscan_options.enumerate_only_vulnerable_themes
    log.info "[+] Enumerating installed themes #{'(only vulnerable ones)' if wpscan_options.enumerate_only_vulnerable_themes} ..."

    options = {}
    options[:base_url]              = wp_target.uri
    options[:only_vulnerable_ones]  = wpscan_options.enumerate_only_vulnerable_themes || false
    options[:show_progress_bar]     = wpscan_options.logfile ? false : true
    options[:wp_content_dir]        = wp_target.wp_content_dir
    options[:error_404_hash]        = wp_target.error_404_hash

    themes = wp_target.themes_from_aggressive_detection(options)
    unless themes.empty?
      log.info "[+] We found #{themes.size.to_s} themes:"

      themes.each do |theme|
        log.info " | Name: #{theme}" #this will also output the version number if detected
        log.info " | Location: #{theme.get_url_without_filename}"
        log.info " | Directory listing enabled: Yes" if theme.directory_listing?
        log.info " | Readme: #{theme.readme_url}" if theme.has_readme?
        log.info " | Changelog: #{theme.changelog_url}" if theme.has_changelog?

        theme.vulnerabilities.each do |vulnerability|
          log.vuln " | [!] #{vulnerability.title}"
          log.vuln " | * Reference: #{vulnerability.reference}"

          # This has been commented out as MSF are moving from
          # XML-RPC to MessagePack.
          # I need to get to grips with the new way of communicating
          # with MSF and implement new code.

          # check if vuln is exploitable
          #Exploit.new(url, type, uri, postdata.to_s, use_proxy, proxy_addr, proxy_port)
        end
      end
    else
      log.info "No themes found :("
    end
  end

  if wpscan_options.enumerate_timthumbs
    log.info "[+] Enumerating timthumb files ..."

    options = {}
    options[:base_url]          = wp_target.uri
    options[:show_progress_bar] = wpscan_options.logfile ? false : true
    options[:wp_content_dir]    = wp_target.wp_content_dir
    options[:error_404_hash]    = wp_target.error_404_hash

    theme_name = wp_theme ? wp_theme.name : nil
    if wp_target.has_timthumbs?(theme_name, options)
      timthumbs = wp_target.timthumbs

      log.info "[+] We found #{timthumbs.size.to_s} timthumb file/s :"

      timthumbs.each do |t|
        log.vuln " | [!] #{t.get_full_url.to_s}"
      end
      log.vuln " * Reference: http://www.exploit-db.com/exploits/17602/"
    else
      log.info "No timthumb files found :("
    end
  end

  # If we haven't been supplied a username, enumerate them...
  if !wpscan_options.username and wpscan_options.wordlist or wpscan_options.enumerate_usernames
    log.info green("[+]") + " Enumerating usernames ..."

    usernames = wp_target.usernames(:range => wpscan_options.enumerate_usernames_range)

    if usernames.empty?
      log.info "We did not enumerate any usernames :("
      log.info "Try supplying your own username with the --username option"
      exit(1)
    else
      log.info "[+] We found the following #{usernames.length.to_s} username/s :"

      max_id_length = usernames.sort { |a, b| a.id.to_s.length <=> b.id.to_s.length }.last.id.to_s.length
      max_name_length = usernames.sort { |a, b| a.name.length <=> b.name.length }.last.name.length
      max_nickname_length = usernames.sort { |a, b| a.nickname.length <=> b.nickname.length }.last.nickname.length

      space = 1
      usernames.each do |u|
        id_string = "id: #{u.id.to_s.ljust(max_id_length + space)}"
        name_string = "name: #{u.name.ljust(max_name_length + space)}"
        nickname_string = "nickname: #{u.nickname.ljust(max_nickname_length + space)}"
        log.info " | #{id_string}| #{name_string}| #{nickname_string}"
      end
    end

  else
    usernames = [WpUser.new(wpscan_options.username, -1, "empty")]
  end

  # Start the brute forcer
  bruteforce = true
  if wpscan_options.wordlist
    if wp_target.has_login_protection?

      protection_plugin = wp_target.login_protection_plugin()

      log.warn "The plugin #{protection_plugin.name} has been detected. It might record the IP and timestamp of every failed login. Not a good idea for brute forcing !"
      log.warn "[?] Do you want to start the brute force anyway ? [y/n]"

      if Readline.readline !~ /^y/i
        bruteforce = false
      end
    end

    if bruteforce === false
      log.info "Brute forcing aborted"
    else
      log.info "[+] Starting the password brute forcer"
      wp_target.brute_force(usernames, wpscan_options.wordlist)
    end
  end

  stop_time = Time.now
  log.info "[+] Finished at #{stop_time.asctime}"
  elapsed = stop_time - start_time
  log.info "[+] Elapsed time: #{Time.at(elapsed).utc.strftime("%H:%M:%S")}"
  exit() # must exit!
rescue => e
  log.error "[ERROR] #{e.message}"
  log.error "Trace :"
  log.error  e.backtrace.join("\n")
end
