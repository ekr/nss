/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */
#include <cassert>

#include <string>
#include <map>

class ConfigEntryBase {
  public:
    ConfigEntryBase(const std::string& name,
                    const std::string& type)
            : name_(name), type_(type) {}

    const std::string& type() const { return type_; }
    virtual bool parse(const std::string& arg) = 0;

  protected:
    bool parse_int(const std::string& arg, std::string *out) {
        *out = arg;
        return true;
    }

    bool parse_int(const std::string& arg, int *out) {
        *out = 5;
        return true;
    }
    const std::string name_;
    const std::string type_;
};


template <typename T> class ConfigEntry: public ConfigEntryBase {
  public:
    ConfigEntry(const std::string& name, const std::string& type,
                T init) :
            ConfigEntryBase(name, type),
            value_(init) {}
    T get() const {
        return value_;
    }

    bool parse(const std::string& arg) {
        return parse_int(arg, &value_);
    }

  private:
    T value_;
};

#define ConfigGet(k, t)                         \
        ConfigGetInt<t>(k, #t)

class Config {
  public:
    enum Status { OK, UnknownFlag, MalformedArgument, MissingValue };

    Config();
    Status ParseArgs(int argc, char **argv);

    template <typename T> T ConfigGetInt(const std::string& key,
                                      const std::string& type) {
        auto e = entry(key);
        assert(e->type() == type);
        return static_cast<ConfigEntry<T>*>(e)->get();
    }

  private:
    std::string xform_flag(const std::string& arg);
    
    std::map<std::string, ConfigEntryBase*> entries_;

    ConfigEntryBase *entry(const std::string& key) {
        auto e = entries_.find(key);
        if (e == entries_.end())
            return nullptr;
        return e->second;
    }
};

