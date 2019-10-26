/// @file utils.hpp
/// @brief Misc. helper classes and wrappers
/// @author Reinaldo Molina
/// @version  0.0
/// @date Oct 26 2019

#ifndef UTILS_HPP
#define UTILS_HPP

class ILog {
public:
  virtual int init() = 0;
  virtual void log(int severity, const char *msg) = 0;

  ILog();
};

class Syslog : ILog {

public:
  Syslog();
};

#endif
