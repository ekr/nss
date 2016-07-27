/* -*- Mode: C++; tab-width: 8; indent-tabs-mode: nil; c-basic-offset: 2 -*- */
/* vim: set ts=2 et sw=2 tw=80: */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this file,
 * You can obtain one at http://mozilla.org/MPL/2.0/. */
#include "config.h"

#include <cstdlib>
#include <algorithm>

#define CONFIG_ENTRY(n, t, i)                   \
  entries_[n] = new ConfigEntry<t>(n, #t, i)

Config::Config() : entries_() {
  CONFIG_ENTRY("flag1", int, 0);
  CONFIG_ENTRY("flag2", std::string, "blah");
}

std::string Config::xform_flag(const std::string& arg) {
  std::string res = "";
  if (arg == "")
    return res;

  if (arg[0] != '-')
    return res;

  return arg.substr(1);
}

Config::Status Config::ParseArgs(int argc, char **argv) {
  for (size_t i = 1; i < argc; ++i) {
    auto e = entries_.find(xform_flag(argv[i]));
    if (e == entries_.end()) {
      return UnknownFlag;
    }

    if (argc < (i + 2)) {
      return MissingValue;
    }

    if (!e->second->parse(argv[i]))
      return MalformedArgument;

    ++i;
  }

  return OK;
}
