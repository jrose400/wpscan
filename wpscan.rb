#!/usr/bin/env ruby

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
#
# ryandewhurst at gmail
#

$: << '.'
require File.dirname(__FILE__) +'/lib/wpscan/wpscan_helper'

banner()

begin
  wpscan_options = WpscanOptions.load_from_arguments
  output         = YamlOutput.new

  unless wpscan_options.has_options?
    raise "No argument supplied\n#{usage()}"
  end

  if wpscan_options.help
    help()
    exit
  end

  # Check for updates
  if wpscan_options.update
    unless @updater.nil?
      output.updater_update(@updater.update())
    else
      output.updater_not_available()
    end
    exit(1)
  end

  wp_target = WpTarget.new(wpscan_options.url, wpscan_options.to_h)

  # Remote website up?
  unless wp_target.is_online?
    raise "The WordPress URL supplied '#{wp_target.uri}' seems to be down."
  end

  if redirection = wp_target.redirection
    if wpscan_options.follow_redirection
      output.following_redirection(redirection)
    else
      output.redirection_detected(redirection)

      output.follow_redirection_question() if output.has_user_interaction?
    end

    if wpscan_options.follow_redirection or (output.has_user_interaction? and Readline.readline =~ /^y/i)
      wpscan_options.url = redirection
      wp_target = WpTarget.new(redirection, wpscan_options.to_h)
    else
      output.scan_aborted()
      exit(1)
    end
  end

  # Remote website is wordpress?
  unless wpscan_options.force
    unless wp_target.is_wordpress?
      raise "The remote website is up, but does not seem to be running WordPress."
    end
  end

  if wp_content_dir = wp_target.wp_content_dir()
    Browser.instance.variables_to_replace_in_url = {"$wp-content$" => wp_content_dir, "$wp-plugins$" => wp_target.wp_plugins_dir()}
  else
    raise "The wp_content_dir has not been found, please supply it with --wp-content-dir"
  end

  # Output runtime data
  output.start_message(wp_target.url, Time.now)

  # Can we identify the theme name?
  if wp_theme = wp_target.theme
    output.wp_theme(wp_theme)
  end

  # Is the readme.html file there?
  if wp_target.has_readme?
    output.wp_readme(wp_target.readme_url)
  end

  # Full Path Disclosure (FPD)?
  if wp_target.has_full_path_disclosure?
    output.full_path_disclosure(wp_target.full_path_disclosure_url)
  end

  output.wp_config_backup(wp_target.config_backup)

  # Checking for malwares
  if wp_target.has_malwares?
    output.malwares(wp_target.malwares)
  end

  # Checking the version...
  if wp_version = wp_target.version
    output.wp_version(wp_version)
  end

  # Plugins from passive detection
  output.wp_plugins_from_passive_detection(wp_target.plugins_from_passive_detection)

  # Enumerate the installed plugins
  if wpscan_options.enumerate_plugins or wpscan_options.enumerate_only_vulnerable_plugins

    output.enumerate_plugins_message(wpscan_options.enumerate_only_vulnerable_plugins)

    output.wp_plugins_from_aggressive_detection(
      wp_target.plugins_from_aggressive_detection(
        :only_vulnerable_ones => wpscan_options.enumerate_only_vulnerable_plugins,
        :show_progress_bar => output.show_progress_bar?
      )
    )
  end

  # try to find timthumb files
  if wpscan_options.enumerate_timthumbs
    output.enumerate_timthumbs_message()
    output.wp_timthumbs(
      wp_target.timthumbs(:theme_name => wp_theme ? wp_theme.name : nil, :show_progress_bar => output.show_progress_bar?)
    )
  end

  # If we haven't been supplied a username, enumerate them...
  if !wpscan_options.username and wpscan_options.wordlist or wpscan_options.enumerate_usernames

    output.enumerate_usernames_message()

    usernames = wp_target.usernames(:range => wpscan_options.enumerate_usernames_range)
    output.wp_usernames(usernames)
  else
    usernames = [wpscan_options.username]
  end

  # Start the brute forcer
  if wpscan_options.wordlist
    bruteforce = false

    if wp_target.has_login_protection?

      protection_plugin = wp_target.login_protection_plugin()

      output.protection_plugin_detected(protection_plugin)

      if output.has_user_interaction?
        output.start_brute_force_question()

        if Readline.readline =~ /^y/i
          bruteforce = true
        end
      end
    end

    if bruteforce === false
      output.brute_force_aborted()
    else
      output.starting_brute_force()

      wp_target.brute_force(
        usernames,
        wpscan_options.wordlist,
        :show_progress_bar => output.show_progress_bar?,
        :output => output
      )
    end
  end

  output.end_message(Time.now)
  exit() # must exit!
rescue => e
  puts "[ERROR] #{e}"
  puts "Trace : #{e.backtrace}"
end
