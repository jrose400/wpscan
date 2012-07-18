#
# WPScan - WordPress Security Scanner
# Copyright (C) 2011  Ryan Dewhurst AKA ethicalhack3r
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

require File.dirname(__FILE__) + "/output"

class ConsoleOutput < Output

  def initialize(options = {})
    super(options.merge(:show_progress_bar => true, :has_user_interaction => true))
  end

  def updater_update(update_results)
    puts update_results
  end

  def updater_not_available
    puts "Svn / Git not installed, or wpscan has not been installed with one of them."
    puts "Update aborted"
  end

  def following_redirection(redirection)
    puts "Following redirection #{redirection}"
    puts
  end

  def redirection_detected(redirection)
    puts "The remote host tried to redirect us to #{redirection}"
  end

  def follow_redirection_question
    puts "Do you want follow the redirection ? [y/n]"
  end

  def scan_aborted
    puts "Scan aborted"
  end

  # param string target_url
  def start_message(target_url, start_time)
    puts "| URL: #{target_url}"
    puts "| Started on #{start_time.asctime}"
    puts
  end

  # param WpTheme wp_theme
  def wp_theme(wp_theme)
    theme_version = wp_theme.version
    puts "[!] The WordPress theme in use is #{wp_theme}"

    theme_vulnerabilities = wp_theme.vulnerabilities
    unless theme_vulnerabilities.empty?
      puts "[+] We have identified #{theme_vulnerabilities.size} vulnerabilities for this theme :"
      theme_vulnerabilities.each do |vulnerability|
        puts
        puts " | * Title: " + vulnerability.title
        puts " | * Reference: " + vulnerability.reference
      end
      puts
    end
  end

  # param string readme_url
  def wp_readme(readme_url)
    puts "[!] The WordPress '#{readme_url}' file exists"
  end

  # param string fpd_url
  def full_path_disclosure(fpd_url)
    puts "[!] Full Path Disclosure (FPD) in '#{fpd_url}'"
  end

  # param array config_backup
  def wp_config_backup(config_backup)
    config_backup.each do |file_url|
      puts "[!] A wp-config.php backup file has been found '#{file_url}'"
    end
  end

  # param array malwares
  def malwares(malwares)
    puts "[!] #{malwares.size} malware(s) found :"

    malwares.each do |malware_url|
      puts
      puts " | " + malware_url
    end
    puts
  end

  # param WpVersion wp_version
  def wp_version(wp_version)
    puts "[!] WordPress version #{wp_version.number} identified from #{wp_version.discovery_method}"

    # Are there any vulnerabilities associated with this version?
    version_vulnerabilities = wp_version.vulnerabilities

    unless version_vulnerabilities.empty?
      puts
      puts "[+] We have identified #{version_vulnerabilities.size} vulnerabilities from the version number :"
      version_vulnerabilities.each do |vulnerability|
        puts
        puts " | * Title: " + vulnerability.title
        puts " | * Reference: " + vulnerability.reference
      end
    end
  end

  # param array of WpPlugin wp_plugins
  def wp_plugins_from_passive_detection(wp_plugins)
    puts
    print "[+] Enumerating plugins from passive detection ... "

    unless wp_plugins.empty?
      print "#{plugins.size} found :\n"

      wp_plugins.each do |plugin|
        puts
        puts " | Name: " + plugin.name
        puts " | Location: " + plugin.location_url

        plugin.vulnerabilities.each do |vulnerability|
          puts " |"
          puts " | [!] " + vulnerability.title
          puts " | * Reference: " + vulnerability.reference
        end
      end
    else
      print "No plugins found :(\n"
    end
  end

  def enumerate_plugins_message(only_vulnerable_plugins = false)
    puts
    puts "[+] Enumerating installed plugins #{'(only vulnerable ones)' if only_vulnerable_plugins} ..."
    puts
  end

  def wp_plugins_from_aggressive_detection(wp_plugins)
    unless wp_plugins.empty?
      puts
      puts
      puts "[+] We found " + wp_plugins.size.to_s  + " plugins:"

      wp_plugins.each do |plugin|
        puts
        puts " | Name: " + plugin.name
        puts " | Location: " + plugin.location_url

        puts " | Directory listing enabled? #{plugin.directory_listing? ? "Yes." : "No."}"

        plugin.vulnerabilities.each do |vulnerability|
          puts " |"
          puts " | [!] " + vulnerability.title
          puts " | * Reference: " + vulnerability.reference
        end

        if plugin.error_log?
          puts " | [!] A WordPress error_log file has been found : " + plugin.error_log_url
        end
      end
    else
      puts
      puts "No plugins found :("
    end
  end

  def enumerate_timthumbs_message
    puts
    puts "[+] Enumerating timthumb files ..."
    puts
  end

  def wp_timthumbs(wp_timthumbs)
    unless wp_timthumbs.empty?
      puts
      puts "[+] We found " + wp_timthumbs.size.to_s  + " timthumb file/s :"
      puts

      wp_timthumbs.each do |file_url|
        puts " | [!] " +  file_url
      end
      puts
      puts " * Reference: http://www.exploit-db.com/exploits/17602/"
    else
      puts
      puts "No timthumb files found :("
    end
  end

  def enumerate_usernames_message
    puts
    puts "[+] Enumerating usernames ..."
  end

  def wp_usernames(wp_usernames)
    if wp_usernames.empty?
      puts
      puts "We did not enumerate any usernames :("
      puts "Try supplying your own username with the --username option"
      puts
      exit(1)
    else
      puts
      puts "We found the following " + wp_usernames.length.to_s + " username/s :"
      puts

      wp_usernames.each {|username| puts "  " + username}
    end
  end

  def protection_plugin_detected(plugin)
    puts
    puts "The plugin #{plugin.name} has been detected. It might record the IP and timestamp of every failed login. Not a good idea for brute forcing !"
  end

  def start_brute_force_question
    puts "[?] Do you want to start the brute force anyway ? [y/n]"
  end

  def brute_force_aborted
    puts "Brute forcing aborted"
  end

  def starting_brute_force
    puts
    puts "[+] Starting the password brute forcer"
    puts
  end

  def verbose(message)
    puts message
  end

  def password_found(username, password)
    puts "\n  [SUCCESS] Username : #{username} Password : #{password}\n"
  end

  def error(message)
    puts message
  end

  def end_message(end_time)
    puts
    puts "[+] Finished at #{end_time.asctime}"
  end

end
