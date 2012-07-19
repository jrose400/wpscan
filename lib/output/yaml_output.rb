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

class YamlOutput < Output

  def updater_update(update_results)
    @update_results = update_results
  end

  def updater_not_available
    @updater_not_available = true
  end

  def following_redirection(redirection)
    @redirection_followed = redirection
  end

  def redirection_detected(redirection)
    @redirection_detected = redirection
  end

  def follow_redirection_question
    # Should not happened
  end

  def scan_aborted
    @scan_aborted = true
  end

  # param string target_url
  def start_message(target_url, start_time)
    @url = target_url
    @start_time = start_time.to_i
  end

  # param WpTheme wp_theme
  def wp_theme(wp_theme)
    wp_theme.version
    wp_theme.vulnerabilities
    @wp_theme = wp_theme
  end

  # param string readme_url
  def wp_readme(readme_url)
    @readme = readme_url
  end

  # param string fpd_url
  def full_path_disclosure(fpd_url)
    @full_path_disclosure = fpd_url
  end

  # param array config_backup
  def wp_config_backup(config_backup)
    @config_backup = config_backup
  end

  # param array malwares
  def malwares(malwares)
    @malwares = malwares
  end

  # param WpVersion wp_version
  def wp_version(wp_version)
    wp_version.vulnerabilities
    @wp_version = wp_version
  end

  # param array of WpPlugin wp_plugins
  def wp_plugins_from_passive_detection(wp_plugins)
    @wp_plugins_from_passive_detection = wp_plugins
  end

  def enumerate_plugins_message(only_vulnerable_plugins = false)
    # None
  end

  def wp_plugins_from_aggressive_detection(wp_plugins)
    unless wp_plugins.empty?
      wp_plugins.each do |plugin|
        plugin.directory_listing?
        plugin.vulnerabilities
        plugin.error_log?
      end
    end
    @wp_plugins_from_aggressive_detection = wp_plugins
  end

  def enumerate_timthumbs_message
    # None
  end

  def wp_timthumbs(wp_timthumbs)
    @wp_timthumbs = wp_timthumbs
  end

  def enumerate_usernames_message
    # None
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
    @end_time = end_time.to_i

    File.open("out.yml", 'w') do |f|
      f.write(YAML.dump(self))
    end
  end

end
