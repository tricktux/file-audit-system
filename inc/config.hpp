/// @file config.hpp
/// @brief Header for config related classes
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 28 2019

#ifndef CONFIG_HPP
#define CONFIG_HPP

#include "dictionary.h"
#include "iniparser.h"
#include <string>
#include <unordered_map>
#include <syslog.h>

class IConfig {
protected:
  std::string file_name;

public:
  IConfig(const std::string &file) : file_name(file) {}
  virtual int load() = 0;
  virtual std::string get_string(const std::string &option,
                                 const std::string &def) const = 0;
};

/// Map option name with default value
struct ConfigOptions {
	std::unordered_map<std::string, std::string> opts;
	ConfigOptions() {
		opts["dir"] = "/etc";
		opts["log"] = "/tmp/file-monitor.log";
		opts["key"] = "file-monitor";
	}
};

class IniConfig : public IConfig {
  dictionary *ini;

public:
  IniConfig(const std::string &file) : IConfig(file), ini(nullptr) {}
  ~IniConfig() {
    if (ini)
      iniparser_freedict(ini);
  }

  int load() override {
    ini = iniparser_load(file_name.c_str());
    if (ini == nullptr) {
      syslog(LOG_ALERT, "Failed parse file: %s\n", file_name.c_str());
      return -1;
    }
    return 0;
  }

  std::string get_string(const std::string &option,
                         const std::string &def) const override {
    const char *pch = nullptr;

    if (option.empty())
      return std::string();
    pch = iniparser_getstring(ini, option.c_str(), def.c_str());
    if (pch == nullptr)
      return std::string();

    return pch;
  }
};



#endif
